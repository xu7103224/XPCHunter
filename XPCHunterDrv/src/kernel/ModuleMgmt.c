// ModuleMgmt.c — 模块管理（从 ModuleMgmt.c 拆分后保留）
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 功能：模块/驱动枚举、相对地址解析、驱动信息构建

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

// LookupModuleByName — 按名称查找模块
// 对应原始驱动 sub_14000C2F8
__int64 *LookupModuleByName(const char *ModuleName, __int64 *OutBaseAddress)
{
    void (__fastcall *StringAllocFunc)(_BYTE *, const char *);
    ULONG (__fastcall *AnsiToUnicodeFunc)(WORD *, _BYTE *, __int64);
    void (__fastcall *FreeStringFunc)(WORD *);
    _DWORD *ModuleBuffer;
    ULONG ModuleCount, ModuleIndex;

    StringAllocFunc = (void (__fastcall *)(_BYTE *, const char *))GtRead(GtStringAllocFunc);
    AnsiToUnicodeFunc = (ULONG (__fastcall *)(WORD *, _BYTE *, __int64))GtRead(GtAnsiToUnicodeFunc);
    FreeStringFunc = (void (__fastcall *)(WORD *))GtRead(GtFreeStringFunc);

    if (!StringAllocFunc || !AnsiToUnicodeFunc || !FreeStringFunc)
        return NULL;

    // Check for "ntoskrnl.exe" match
    char NtName[] = "ntoskrnl.exe";
    if (strcmp(NtName, ModuleName) == 0)
    {
        __int64 *Result = GtAlloc(GtPathBuffer00);
        *OutBaseAddress = GtRead(GtNtoskrnlModuleBase);
        return *OutBaseAddress ? Result : NULL;
    }

    ModuleBuffer = (_DWORD *)GtRead(GtModuleBuffer);
    if (!ModuleBuffer)
        return NULL;

    _BYTE AnsiNameBuffer[16];
    WORD UnicodeNameLen;

    StringAllocFunc(AnsiNameBuffer, ModuleName);
    if (AnsiToUnicodeFunc(&UnicodeNameLen, AnsiNameBuffer, 1))
        return NULL;

    ModuleCount = *ModuleBuffer;
    for (ModuleIndex = 0; ModuleIndex < ModuleCount; ModuleIndex++)
    {
        WORD *CurrentName = (WORD *)(ModuleBuffer + 138 * ModuleIndex + 11);
        if (*CurrentName)
        {
            WORD *LastChar = WStringFindLastChar(CurrentName, L'\\');
            WORD *FileName = LastChar ? LastChar + 1 : CurrentName;
            ULONG FileNameLen = 2 * (ULONG)GetStringLength(FileName);

            if (FileNameLen == UnicodeNameLen &&
                StringCompare3Way((__int64)FileName, (unsigned __int16 *)&UnicodeNameLen, FileNameLen >> 1) == 0)
            {
                __int64 *Result = (__int64 *)&ModuleBuffer[138 * ModuleIndex + 11];
                *OutBaseAddress = *(__int64 *)&ModuleBuffer[138 * ModuleIndex + 8];
                FreeStringFunc(&UnicodeNameLen);
                return Result;
            }
        }
    }

    FreeStringFunc(&UnicodeNameLen);
    return NULL;
}
_DWORD *FindExportByAddress(ULONG64 TargetAddress)
{
    _DWORD *ModuleBuffer;
    ULONG EntryIndex;

    ModuleBuffer = (_DWORD *)GtRead(GtModuleBuffer);
    if (!ModuleBuffer || !*ModuleBuffer)
        return NULL;

    for (EntryIndex = 0; EntryIndex < *ModuleBuffer; EntryIndex++)
    {
        _DWORD *Entry = ModuleBuffer + 138 * EntryIndex;
        if (*(ULONG64 *)Entry <= TargetAddress &&
            *(ULONG64 *)Entry + (ULONG64)Entry[2] > TargetAddress)
            return &ModuleBuffer[138 * EntryIndex + 11];
    }

    return NULL;
}
void *FindExportEntryByName(char *Dst)
{
    _DWORD *ModuleBuffer;
    ULONG ModuleCount, EntryIndex;

    ModuleBuffer = (_DWORD *)GtRead(GtModuleBuffer);
    if (!ModuleBuffer)
        return memset(Dst, 0, 0x228);

    ModuleCount = *ModuleBuffer;
    if (!ModuleCount)
        return memset(Dst, 0, 0x228);

    for (EntryIndex = 0; EntryIndex < ModuleCount; EntryIndex++)
    {
        _DWORD *Entry = ModuleBuffer + 138 * EntryIndex + 10;
        if (*((__int64 *)Entry - 1) == *(__int64 *)(Dst + 24) &&
            *Entry == *(ULONG *)(Dst + 32) &&
            WStringCompare((__int64)(ModuleBuffer + 138 * EntryIndex + 11), (WORD *)(Dst + 36), 0x100) == 0)
        {
            ULONG NextIndex = EntryIndex + 1;
            if (NextIndex >= ModuleCount)
                return memset(Dst, 0, 0x228);

            _OWORD *NextEntry = (_OWORD *)&ModuleBuffer[138 * NextIndex + 2];
            for (ULONG q = 0; q < 4; q++)
            {
                *(_OWORD *)Dst = NextEntry[0];
                *((_OWORD *)Dst + 1) = NextEntry[1];
                *((_OWORD *)Dst + 2) = NextEntry[2];
                *((_OWORD *)Dst + 3) = NextEntry[3];
                *((_OWORD *)Dst + 4) = NextEntry[4];
                *((_OWORD *)Dst + 5) = NextEntry[5];
                *((_OWORD *)Dst + 6) = NextEntry[6];
                _OWORD Data = NextEntry[7];
                Dst += 128;
                NextEntry += 8;
                *((_OWORD *)Dst - 1) = Data;
            }
            *(_OWORD *)Dst = NextEntry[0];
            *((_OWORD *)Dst + 1) = NextEntry[1];
            void *result = (void *)NextEntry[4].qword[0];
            *((__int64 *)Dst + 4) = (__int64)result;
            return result;
        }
    }

    return memset(Dst, 0, 0x228);
}
__int64 CmdEnumKernelModules(_OWORD *Address, int InputSize, volatile void *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    _OWORD Buffer;
    __int64 ProcessInfoSize;

    if (!Address || InputSize != 24 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)Address + 24 >= MmUserProbeAddress ||
        !OutputBuffer || BufferSize <= 0x50 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, 0x18, 4);
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    Buffer = *Address;
    ProcessInfoSize = *((__int64 *)Address + 2);
    return EnumProcessInformationWorker((char *)&Buffer, (__int64)OutputBuffer, (unsigned int)ProcessInfoSize);
}
// 【GT 索引修正 2026-10-13】原用十进制 2075/2076(=0x81B/0x81C)，
//   原始为 **0x89C / 0x89D**（依据原始 0x1400457A4 的
//   `mov r14d,0x89c` @0x1400457C3 与 `mov r14d,0x89d` @0x1400457E9，
//   随后各 `mov ecx,r14d; call GtRead`，第一个槽共读 3 次=懒初始化）。
__int64 CmdEnumProcessModules(__int64 DeviceObject, __int64 Irp, _DWORD *pOutputBuffer, unsigned int BufferSize)
{
    ULONG64 RemainingSize = BufferSize;
    int Result = 0;
    _QWORD *pModuleList1, *pModuleList2;
    ULONG RemainingSize1, RemainingSize2, RemainingSize3;
    _DWORD *pType1Entry, *pType2Entry, *pType1Header, *pType2Header;
    int Type1Count;
    _QWORD *pType1Node, *i;

    pModuleList1 = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)0x89C);
    if (!pModuleList1)
    {
        ParseNtSectionsForModuleList1();
        pModuleList1 = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)0x89C);
    }

    pModuleList2 = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)0x89D);
    if (!pModuleList2)
    {
        ParseNtSectionsForModuleList2();
        pModuleList2 = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)0x89D);
    }

    if ((RemainingSize & 3) != 0 || (ULONG)RemainingSize < 0x50 ||
        (ULONG64)pOutputBuffer >= MmUserProbeAddress ||
        (ULONG64)pOutputBuffer + RemainingSize >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(pOutputBuffer, RemainingSize, 1);
    memset(pOutputBuffer, 0, RemainingSize);

    RemainingSize1 = (ULONG)(RemainingSize - 40);
    if (RemainingSize1 >= 0x28)
    {
        pType1Header = pOutputBuffer;
        *pOutputBuffer = 1;
        pOutputBuffer[4] = 0;
        RemainingSize2 = RemainingSize1 - 24;
        pType1Entry = pOutputBuffer + 6;

        if (pModuleList1 && MmIsAddressValid(pModuleList1) == 1)
        {
            Type1Count = 0;
            for (pType1Node = (_QWORD *)*pModuleList1;
                 pType1Node != pModuleList1;
                 pType1Node = (_QWORD *)*pType1Node)
            {
                if ((ULONG64)pType1Node <= (ULONG64)MmSystemRangeStart) break;
                if (++Type1Count > 0x10000 ||
                    MmIsAddressValid(pType1Node) != 1 ||
                    MmIsAddressValid((char *)pType1Node + 39) != 1) break;

                if (RemainingSize2 >= 0x10)
                {
                    RemainingSize2 -= 16;
                    pType1Entry += 4;
                    *(__int64 *)&pType1Header[4 * pType1Header[4] + 6] = (__int64)pType1Node;
                    *(__int64 *)&pType1Header[4 * pType1Header[4]++ + 8] = pType1Node[3];
                }
            }
        }

        if (RemainingSize2 >= 0x28)
        {
            pType2Header = pType1Entry;
            *pType1Entry = 2;
            pType1Entry[4] = 0;
            RemainingSize3 = RemainingSize2 - 24;
            pType2Entry = pType1Entry + 6;

            if (pModuleList2 && MmIsAddressValid(pModuleList2) == 1)
            {
                for (i = (_QWORD *)*pModuleList2; i != pModuleList2; i = (_QWORD *)*i)
                {
                    if ((ULONG64)i <= (ULONG64)MmSystemRangeStart) break;
                    if (++Result > 0x10000 ||
                        MmIsAddressValid(i) != 1 ||
                        MmIsAddressValid((char *)i + 39) != 1) break;

                    if (RemainingSize3 >= 0x10)
                    {
                        RemainingSize3 -= 16;
                        pType2Entry += 4;
                        *(__int64 *)&pType2Header[4 * pType2Header[4] + 6] = (__int64)i;
                        *(__int64 *)&pType2Header[4 * pType2Header[4]++ + 8] = i[3];
                    }
                }
            }
        }
    }

    return 1;
}
char ParseNtKernelFile(__int64 ModuleEntry, __int64 OutputBuffer, int OutputSize)
{
    char Result = 0, ReadResult;
    PVOID RawDataBuf;
    void *NtImageBuffer;
    ULONG NtImageSize;
    __int64 NtImageBase;
    ULONG RemainingSize, RemainingSize2, RemainingSize3, RemainingSize4, RemainingSize5, RemainingSize6;
    ULONG ExportCount1;
    ULONG64 ExportEntryPtr, ExportEntryPtr2, ExportEntryPtr3, ExportEntryPtr4, ExportEntryPtr5;
    __int64 ExportEntryCount, ModuleBase, KernelRoutineTable;
    __int64 BytesWritten;
    __int64 Win32kTable;
    ULONG Win32kEntryCount;
    size_t MaxCount;
    void *NtImageBuffer2, *Src;
    __int64 KernelRoutineCount;

    if (ReadFileRawData((WORD *)(ModuleEntry + 36), &Src, (ULONG *)&MaxCount, 1))
        return Result;

    ReadResult = ReadNtFileToBuffer((PUCHAR)Src, (ULONG)MaxCount, (PUCHAR *)&NtImageBuffer2, &NtImageSize);
    ExFree(Src);
    if (ReadResult != 1) return Result;

    RawDataBuf = ExAlloc(PagedPool, NtImageSize + 256);
    NtImageBuffer = RawDataBuf;
    if (!RawDataBuf) { ExFree(NtImageBuffer2); return Result; }

    memset(RawDataBuf, 0, NtImageSize + 256);
    if (ReadFileIntoBuffer(*(_QWORD *)(ModuleEntry + 24), NtImageSize, (char *)NtImageBuffer) != 1 ||
        ComparePeHeaders((__int64)NtImageBuffer, NtImageSize, (__int64)NtImageBuffer2, NtImageSize))
    {
        ExFree(NtImageBuffer);
        ExFree(NtImageBuffer2);
        return Result;
    }

    WStringCopyN((WORD *)OutputBuffer, ModuleEntry + 36, 0x104);
    NtImageSize = NtImageSize;
    NtImageBase = (__int64)NtImageBuffer2;
    *(WORD *)(OutputBuffer + 518) = 0;
    RemainingSize = OutputSize - 536;

    ExportCount1 = (ULONG)ParseExportDirAndBuildIndex((__int64)NtImageBase, NtImageSize,
        *(_QWORD *)(ModuleEntry + 24), (__int64)NtImageBuffer,
        OutputBuffer + 536, RemainingSize);
    *(_DWORD *)(OutputBuffer + 520) = ExportCount1;

    if (ExportCount1)
    {
        RemainingSize2 = RemainingSize - 620 * ExportCount1;
        ExportEntryPtr = 620LL * ExportCount1 + OutputBuffer + 536;
    }
    else
    {
        RemainingSize2 = RemainingSize - 620;
        ExportEntryPtr = OutputBuffer + 1156;
    }

    if (RemainingSize2 >= 0x2A8)
        *(_DWORD *)(OutputBuffer + 524) = (_DWORD)ParseExportDirectoryEntries(
            (__int64)NtImageBuffer2, NtImageSize, *(_QWORD *)(ModuleEntry + 24),
            (__int64)NtImageBuffer, ExportEntryPtr, RemainingSize2);

    if (ParseNtExportDir((PUCHAR)NtImageBuffer2, NtImageSize, *(_QWORD *)(ModuleEntry + 24), 0) == 1)
    {
        ExportEntryCount = *(unsigned int *)(OutputBuffer + 524);
        if (ExportEntryCount)
        {
            RemainingSize3 = (ULONG)(RemainingSize2 - 680 * ExportEntryCount);
            ExportEntryPtr2 = ExportEntryPtr + 680 * ExportEntryCount;
        }
        else
        {
            RemainingSize3 = RemainingSize2 - 680;
            ExportEntryPtr2 = ExportEntryPtr + 680;
        }

        if (RemainingSize3 >= 0x25E)
        {
            ModuleBase = *(_QWORD *)(ModuleEntry + 24);
            ExportEntryPtr3 = ExportEntryPtr2;
            ExportEntryPtr2 = ExportEntryPtr2;
            *(_DWORD *)(OutputBuffer + 528) = (_DWORD)ParseNtExportDirTable(
                (__int64)NtImageBuffer2, NtImageSize, ModuleBase, (__int64)NtImageBuffer,
                ExportEntryPtr2, RemainingSize3, (_DWORD *)&BytesWritten);

            if ((ULONG)GtRead(GtWin32kServiceTableVersion) == 2)
            {
                BytesWritten = BytesWritten;
                if (RemainingSize3 >= BytesWritten)
                {
                    RemainingSize4 = RemainingSize3 - (ULONG)BytesWritten;
                    if (RemainingSize4 >= 0x25E)
                    {
                        KernelRoutineCount = GtRead(GtKernelRoutineTableCount);
                        if (!KernelRoutineCount)
                        {
                            InitKernelRoutineTable();
                            KernelRoutineCount = GtRead(GtKernelRoutineTableCount);
                        }
                        KernelRoutineTable = GtRead(GtKernelRoutineTable);
                        ExportEntryPtr4 = BytesWritten + ExportEntryPtr2;
                        *(_DWORD *)(OutputBuffer + 528) += (_DWORD)ParseExportEntriesDetailed(
                            KernelRoutineTable, (unsigned int)KernelRoutineCount, (__int64)NtImageBuffer2, NtImageSize, *(_QWORD *)(ModuleEntry + 24),
                            (__int64)NtImageBuffer, ExportEntryPtr4, RemainingSize4,
                            (_DWORD *)&BytesWritten, ExportEntryPtr2, *(_DWORD *)(OutputBuffer + 528));

                        if (RemainingSize4 >= BytesWritten)
                        {
                            RemainingSize5 = RemainingSize4 - (ULONG)BytesWritten;
                            if (RemainingSize5 >= 0x25E)
                            {
                                Win32kTable = GtRead(GtWin32kServiceTable);
                                if (!Win32kTable)
                                {
                                    InitWin32kServiceTableEntries();
                                    Win32kTable = GtRead(GtWin32kServiceTable);
                                }
                                Win32kEntryCount = (ULONG)GtRead(GtWin32kServiceEntryCount);
                                ExportEntryPtr5 = BytesWritten + ExportEntryPtr4;
                                *(_DWORD *)(OutputBuffer + 528) += (_DWORD)ParseExportEntriesDetailed(
                                    Win32kTable, Win32kEntryCount, (__int64)NtImageBuffer2, NtImageSize,
                                    *(_QWORD *)(ModuleEntry + 24), (__int64)NtImageBuffer,
                                    ExportEntryPtr5, RemainingSize5, (_DWORD *)&BytesWritten, ExportEntryPtr2,
                                    *(_DWORD *)(OutputBuffer + 528));

                                if (RemainingSize5 >= BytesWritten)
                                {
                                    RemainingSize3 = RemainingSize5 - (ULONG)BytesWritten;
                                    if (RemainingSize3 >= 0x25E)
                                    {
                                        ExportEntryPtr2 = BytesWritten + ExportEntryPtr5;
                                        *(_DWORD *)(OutputBuffer + 528) += (_DWORD)ParseNtExportAuxData(
                                            (__int64)NtImageBuffer2, NtImageSize, *(_QWORD *)(ModuleEntry + 24),
                                            (unsigned int)(ULONG_PTR)NtImageBuffer, ExportEntryPtr2,
                                            RemainingSize3, (_DWORD *)&BytesWritten);
                                        ExportEntryPtr3 = ExportEntryPtr2;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (RemainingSize3 >= BytesWritten)
            {
                RemainingSize6 = RemainingSize3 - (ULONG)BytesWritten;
                if (RemainingSize6 >= 0x25E)
                    *(_DWORD *)(OutputBuffer + 532) = (_DWORD)ParseAndCompareExportEntries(
                        (__int64)NtImageBuffer2, NtImageSize, *(_QWORD *)(ModuleEntry + 24),
                        (__int64)NtImageBuffer, ExportEntryPtr2 + BytesWritten,
                        RemainingSize6, ExportEntryPtr3, *(_DWORD *)(OutputBuffer + 528));
            }
        }
    }

    Result = 1;
    ExFree(NtImageBuffer);
    ExFree(NtImageBuffer2);
    return Result;
}
void NormalizeModulePaths(__int64 OutputBuffer, unsigned int EntryCount)
{
    WORD *SystemRoot, *DriversPath, *DriversPathBuf;
    WORD *TempBuffer;
    short *PathPtr, *Char, *ColonPos, *BackslashPos2;
    int StrLen, StringLength;
    WORD DriveLetter[2];
    ULONG PathOffset;
    _DWORD EncodedPrefix[3];
    __int64 EncodedPrefixHigh;
    ULONG EntryIndex;

    SystemRoot = InitSystemPath();
    DriversPath = BuildDriversPath();
    DriversPathBuf = DriversPath;

    if (!SystemRoot || !DriversPath) goto Cleanup;

    EncodedPrefix[0] = 4456540;
    EncodedPrefix[1] = 7733349;
    EncodedPrefix[2] = 6488169;
    EncodedPrefixHigh = 6029413;

    TempBuffer = ExAlloc(PagedPool, 0x410);
    if (!TempBuffer) goto Cleanup;

    PathPtr = (short *)(OutputBuffer + 1584);
    for (EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++)
    {
        if (!*PathPtr) goto NextEntry;

        Char = WStringFindChar(PathPtr, L'\\');
        if (!Char)
        {
            WStringCopyN(TempBuffer, (__int64)DriversPathBuf, 0x104);
            TempBuffer[259] = 0;
            if (GetStringLength(TempBuffer) < 0x103)
            {
                StrLen = (int)GetStringLength(TempBuffer);
                WStringConcat(TempBuffer, PathPtr, 259 - StrLen);
                TempBuffer[259] = 0;
            }
            WStringCopyN(PathPtr, (__int64)TempBuffer, 0x104);
            goto NextEntry;
        }

        ColonPos = WStringFindChar(PathPtr, L':');
        if (ColonPos)
        {
            if (ColonPos[1] != L'\\' || PathPtr == ColonPos)
                goto NextEntry;
            WStringCopy(TempBuffer, ColonPos - 1);
            WStringCopy(PathPtr, TempBuffer);
            goto NextEntry;
        }

        if (StringCompare3Way((__int64)EncodedPrefix, (WORD *)PathPtr, 8))
        {
            if (Char[1])
            {
                BackslashPos2 = WStringFindChar(Char + 1, L'\\');
                if (BackslashPos2)
                {
                    WStringCopyN(TempBuffer, (__int64)BackslashPos2, 0x104);
                    TempBuffer[259] = 0;
                    WStringCopyN(PathPtr, (__int64)SystemRoot, 0x104);
                    PathPtr[259] = 0;
                    if (GetStringLength(PathPtr) < 0x103)
                    {
                        StringLength = (int)GetStringLength(PathPtr);
                        WStringConcat(PathPtr, TempBuffer, 259 - StringLength);
                        PathPtr[259] = 0;
                    }
                }
            }
            goto NextEntry;
        }

        if (BuildDevicePathFromObjects((WORD *)PathPtr, DriveLetter, (int *)&PathOffset) == 1)
        {
            TempBuffer[0] = DriveLetter[0];
            TempBuffer[1] = L':';
            WStringCopyN(TempBuffer + 2, (__int64)&PathPtr[PathOffset], 0x102);
            TempBuffer[259] = 0;
            WStringCopy(PathPtr, TempBuffer);
        }

NextEntry:
        PathPtr += 1052;
    }

    ExFree(TempBuffer);
Cleanup:
    if (SystemRoot) ExFree(SystemRoot);
    if (DriversPathBuf) ExFree(DriversPathBuf);
}
char ComparePeHeaders(__int64 Image1, unsigned int Image1Size, __int64 Image2, unsigned int Image2Size)
{
    char Result = 0;

    if (Image1 && Image2 && Image1Size > 0x40 && Image2Size > 0x40)
    {
        unsigned int PeOffset1 = *(unsigned int *)(Image1 + 60);
        unsigned int PeOffset2 = *(unsigned int *)(Image2 + 60);

        if (PeOffset1 != PeOffset2)
            return 1;

        if (PeOffset1 < Image1Size && PeOffset1 + 24 < (unsigned __int64)Image1Size &&
            PeOffset2 < Image2Size && PeOffset2 + 24 < (unsigned __int64)Image2Size)
        {
            if (*(WORD *)(PeOffset1 + Image1 + 6) != *(WORD *)(PeOffset2 + Image2 + 6))
                return 1;

            unsigned int SectionCount = *(unsigned __int16 *)(PeOffset1 + Image1 + 20);
            if (SectionCount < Image1Size && SectionCount + PeOffset1 + 24 < (unsigned __int64)Image1Size)
            {
                unsigned int SectionCount2 = *(unsigned __int16 *)(PeOffset2 + Image2 + 20);
                if (SectionCount2 < Image2Size && SectionCount2 + PeOffset2 + 24 < (unsigned __int64)Image2Size &&
                    (*(_DWORD *)(PeOffset1 + Image1 + 40) != *(_DWORD *)(PeOffset2 + Image2 + 40) ||
                     *(_DWORD *)(PeOffset1 + Image1 + 80) != *(_DWORD *)(PeOffset2 + Image2 + 80) ||
                     *(_DWORD *)(PeOffset1 + Image1 + 88) != *(_DWORD *)(PeOffset2 + Image2 + 88)))
                {
                    return 1;
                }
            }
        }
    }
    return Result;
}
char EnumerateDriverList(unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char IsReady = 0;
    __int64 NtoskrnlBase;
    unsigned __int8 (*pValidateFunc)(void);
    unsigned __int64 NtoskrnlImageBase;
    unsigned int NtoskrnlImageSize;
    unsigned __int64 pModuleList;
    unsigned __int64 ListHead;
    unsigned int EntryCount;
    char IsFirst;
    int EntryIndex;
    unsigned int IterationCount = 0;

    NtoskrnlBase = GtRead(GtDriverObject);
    pValidateFunc = (unsigned __int8 (*)(void))GtRead(GtObjectTypeCheckFlag);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (unsigned int)GtRead(GtNtoskrnlImageSize);

    if (!NtoskrnlBase || !pValidateFunc || OutputSize <= 4 || !NtoskrnlImageBase || !NtoskrnlImageSize)
        return IsReady;

    pModuleList = GtRead(GtCallbackField112);
    if (!pModuleList)
        pModuleList = **(_QWORD **)(NtoskrnlBase + 40);

    ListHead = pModuleList;
    EntryCount = 0;
    IsFirst = 1;
    while (ListHead != pModuleList || IsFirst == 1)
    {
        if (pModuleList <= (unsigned __int64)MmSystemRangeStart)
            break;
        EntryCount++;
        IsFirst = 0;
        if (EntryCount > 0x1000 || *(_QWORD *)(pModuleList + 48) == NtoskrnlImageBase)
            break;
        pModuleList = *(_QWORD *)pModuleList;
    }

    unsigned __int64 ListHeadCopy = pModuleList;
    unsigned __int64 pModuleListCopy = pModuleList;
    EntryIndex = 0;
    __int64 pOutputEntry = (__int64)&pOutputBuffer[138 * *pOutputBuffer + 2];
    unsigned int CurrentOffset = 552 * *pOutputBuffer + 560;
    IsFirst = 1;

    while (1)
    {
        if (ListHeadCopy == pModuleList && IsFirst != 1)
            return IsReady;
        if (pModuleList <= (unsigned __int64)MmSystemRangeStart)
            return IsReady;
        if (CurrentOffset > OutputSize)
            return IsReady;

        IterationCount++;
        IsFirst = 0;
        if (IterationCount > 0x1000)
            return IsReady;

        if (pModuleList > NtoskrnlImageBase && pModuleList < NtoskrnlImageBase + NtoskrnlImageSize)
        {
            pModuleList = *(_QWORD *)pModuleList;
            ListHeadCopy = pModuleListCopy;
            IsFirst = 0;
            continue;
        }

        if (LookupDriverObjectEntry(pOutputBuffer, pModuleList, 0, 0) != 1)
        {
            pModuleList = *(_QWORD *)pModuleList;
            ListHeadCopy = pModuleListCopy;
            IsFirst = 0;
            continue;
        }

        *(WORD *)pOutputEntry = 256;
        *(_QWORD *)(pOutputEntry + 8) = pModuleList;
        *(_DWORD *)(pOutputEntry + 4) = EntryIndex;
        *(_QWORD *)(pOutputEntry + 16) = 0;
        EntryIndex++;
        *(_QWORD *)(pOutputEntry + 24) = *(_QWORD *)(pModuleList + 48);
        *(_DWORD *)(pOutputEntry + 32) = *(_DWORD *)(pModuleList + 64);

        if (*(_QWORD *)(pOutputEntry + 24) < (unsigned __int64)MmSystemRangeStart)
        {
            *(_QWORD *)(pOutputEntry + 24) = 0;
            *(UCHAR *)pOutputEntry = 1;
        }

        if (*(_QWORD *)(pModuleList + 80) && *(_QWORD *)(pModuleList + 96))
        {
            ULONG NameLength = (ULONG)(*(WORD *)(pModuleList + 72) & 0xFFFE);
            if (NameLength > 0x1FE)
                NameLength = 510;

            if (*(_QWORD *)(pModuleList + 80) && pValidateFunc() == 1 &&
                ((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(NameLength + *(_QWORD *)(pModuleList + 80) - 1) == 1)
            {
                memmove((void *)(pOutputEntry + 36), *(const void **)(pModuleList + 80), NameLength);
                *(WORD *)(pOutputEntry + 546) = 0;
            }
            else
            {
                *(WORD *)(pOutputEntry + 36) = 0;
                if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x295A)
                    BuildDriverImagePath(pModuleList + 88, *(_DWORD *)(pOutputEntry + 4), pOutputEntry + 36);
                else
                    *(UCHAR *)pOutputEntry = 1;
            }

            if (!*(WORD *)(pOutputEntry + 36))
            {
                ULONG NameLength2 = (ULONG)(*(WORD *)(pModuleList + 88) & 0xFFFE);
                if (NameLength2 > 0x1FE)
                    NameLength2 = 510;

                if (*(_QWORD *)(pModuleList + 96) && pValidateFunc() == 1)
                {
                    if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(NameLength2 + *(_QWORD *)(pModuleList + 96) - 1) == 1)
                    {
                        ULONG NameIndex = 0;
                        if (NameLength2)
                        {
                            char *pNameBuffer = *(char **)(pModuleList + 96);
                            while (*pNameBuffer >= 0)
                            {
                                NameIndex++;
                                pNameBuffer++;
                                if (NameIndex >= NameLength2)
                                    break;
                            }
                        }
                        memmove((void *)(pOutputEntry + 36), *(const void **)(pModuleList + 96), NameLength2);
                        *(WORD *)(pOutputEntry + 546) = 0;
                    }
                }
            }
        }
        else
        {
            if (!*(_QWORD *)(pModuleList + 80))
            {
                UCHAR Flag = *(UCHAR *)pOutputEntry;
                if (*(WORD *)(pModuleList + 72) - 1 <= 0xFFEu)
                    Flag = 1;
                *(UCHAR *)pOutputEntry = Flag;
            }
            if (!*(_QWORD *)(pModuleList + 96))
            {
                *(UCHAR *)pOutputEntry = 1;
            }

            ULONG NameLength = (ULONG)(*(WORD *)(pModuleList + 72) & 0xFFFE);
            if (NameLength > 0x1FE)
                NameLength = 510;

            if (*(_QWORD *)(pModuleList + 80) && pValidateFunc() == 1 &&
                ((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(NameLength + *(_QWORD *)(pModuleList + 80) - 1) == 1)
            {
                memmove((void *)(pOutputEntry + 36), *(const void **)(pModuleList + 80), NameLength);
                *(WORD *)(pOutputEntry + 546) = 0;
            }
            else
            {
                *(WORD *)(pOutputEntry + 36) = 0;
            }
        }

        IsReady = 1;
        CurrentOffset += 552;
        pOutputEntry += 552;
        ++*pOutputBuffer;
        pModuleList = *(_QWORD *)pModuleList;
        ListHeadCopy = pModuleListCopy;
        IsFirst = 0;
    }
    return IsReady;
}
char EnumerateDriverObjects(unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result = 0;
    _DWORD *pTypeTable;
    _QWORD ***pDeviceType;
    unsigned __int8 (*ValidateFunc)(_QWORD *);
    unsigned int BuildNumber;
    _QWORD **pTypeList;
    _QWORD *pListHead;
    int IterationCount;
    unsigned int CurrentOffset;
    unsigned int *pOutputEntry;
    _QWORD *pListEntry;
    __int64 pOutputEntryVal;
    _QWORD **pTypeListCopy;
    char IsReady = 0;

    pTypeTable = (_DWORD *)GtRead(GtTotalSize | GtDeviceObjectProtectOffset);
    if (!pTypeTable || (*pTypeTable & 0x4000) == 0)
        return Result;

    pDeviceType = (_QWORD ***)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
    ValidateFunc = (unsigned __int8 (*)(_QWORD *))GtRead(GtObjectTypeCheckFlag);
    if (!pDeviceType || !ValidateFunc || OutputSize <= 4)
        return Result;

    BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
    pTypeList = *pDeviceType;
    if (BuildNumber <= 0x1770)
        pTypeList += 7;

    pListHead = *pTypeList;
    IterationCount = 0;
    CurrentOffset = 552 * *pOutputBuffer + 560;
    pTypeListCopy = pTypeList;
    pOutputEntry = &pOutputBuffer[138 * *pOutputBuffer + 2];

    if (*pTypeList == (_QWORD *)pTypeList)
        return Result;

    do
    {
        if (CurrentOffset >= OutputSize)
            break;
        if ((ULONG_PTR)pListHead <= (ULONG_PTR)MmSystemRangeStart)
            break;
        if ((unsigned int)++IterationCount > 0x10000)
            break;

        pListEntry = pListHead + 10;
        if (pListHead != (_QWORD *)-80LL)
        {
            pOutputEntryVal = (__int64)pOutputEntry;
            do
            {
                if (ValidateFunc(pListEntry) != 1)
                    break;
                if (CurrentOffset >= OutputSize)
                    break;
                if ((unsigned int)++IterationCount > 0x10000)
                    break;

                if (ValidateDriverObjectAddress(pListEntry[1], pListEntry[1], 1, pOutputBuffer, OutputSize, pOutputEntryVal) == 1)
                {
                    IsReady = 1;
                    CurrentOffset += 552;
                    pOutputEntryVal += 552;
                    ++*pOutputBuffer;
                }
                pListEntry = (_QWORD *)pListEntry[3];
            } while (pListEntry);

            pOutputEntry = (unsigned int *)pOutputEntryVal;
            pTypeList = pTypeListCopy;
        }

        if (ValidateFunc(pListHead) != 1)
            break;
        pListHead = (_QWORD *)*pListHead;
    } while ((ULONG_PTR)pListHead != (ULONG_PTR)pTypeList);

    return IsReady;
}
__int64 (__fastcall *__fastcall EnumerateDriverObjectsEx(unsigned int *pOutputBuffer, unsigned int OutputSize))(_QWORD)
{
    void (__fastcall *pDecodeFunc)(_BYTE *, int *);
    __int64 (__fastcall *pOpenKeyFunc)(_QWORD *, __int64, int *);
    int (__fastcall *pCreateFileFunc)(_QWORD, __int64, _QWORD, _QWORD, void **, _QWORD);
    void (__fastcall *pCloseFunc)(void *);
    __int64 (__fastcall *pUnmapFunc)(_QWORD);
    PVOID *pBuffer;
    PVOID *pObjectBuffer;
    _QWORD ContextArray[4];
    _BYTE DecodedBuffer[16];
    int SectionInfo;
    __int64 MappedBase;
    _BYTE *DecodedPath;
    int Flags;
    _OWORD ZeroStruct;
    int EncodedChar;
    void *pMappedSection;

    pDecodeFunc = (void (__fastcall *)(_BYTE *, int *))GtRead(GtRtlInitUnicodeStringFunc);
    pOpenKeyFunc = (__int64 (__fastcall *)(_QWORD *, __int64, int *))GtRead(GtDeviceIoControlFunc);
    pCreateFileFunc = (int (__fastcall *)(_QWORD, __int64, _QWORD, _QWORD, void **, _QWORD))GtRead(GtNtFsControlFileFunc);
    pCloseFunc = (void (__fastcall *)(void *))GtRead(GtCloseHandleFunc);
    ContextArray[1] = (_QWORD)pCloseFunc;
    pUnmapFunc = (__int64 (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);
    ContextArray[2] = (_QWORD)pUnmapFunc;

    if (!pDecodeFunc || !pOpenKeyFunc || !pCreateFileFunc || !pCloseFunc || !pUnmapFunc)
        return (__int64 (__fastcall *)(_QWORD))pUnmapFunc;

    EncodedChar = 92;
    pDecodeFunc(DecodedBuffer, &EncodedChar);
    SectionInfo = 48;
    MappedBase = 0;
    Flags = 576;
    DecodedPath = DecodedBuffer;
    memset(&ZeroStruct, 0, sizeof(ZeroStruct));

    if ((int)pOpenKeyFunc(ContextArray, 1, &SectionInfo) < 0)
        return (__int64 (__fastcall *)(_QWORD))pUnmapFunc;

    if (pCreateFileFunc(ContextArray[0], 983055, 0, 0, &pMappedSection, 0) >= 0)
    {
        pBuffer = (PVOID *)ExAlloc(PagedPool, 0x100000);
        pObjectBuffer = pBuffer;
        ContextArray[3] = (_QWORD)pBuffer;
        if (pBuffer)
        {
            *pBuffer = pMappedSection;
            EnumerateKernelDrivers(pBuffer, 0x20000, pOutputBuffer, OutputSize);
            ExFree(pObjectBuffer);
        }
        pCloseFunc(pMappedSection);
    }
    return (__int64 (__fastcall *)(_QWORD))pUnmapFunc(ContextArray[0]);
}
__int64 EnumerateDriverObjectsFull(unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    __int64 pValidateFunc;
    __int64 pLookupFunc;
    __int64 pCheckFunc;
    __int64 pCheckFlagFunc;
    __int64 pNtoskrnlBase;
    __int64 pRangeStart;
    __int64 pRangeEnd;
    __int64 pTargetType;
    PVOID pBuffer;
    __int64 CurrentAddr;
    __int64 RangeEnd;
    __int64 RangeStart;
    __int64 pTypeValue;
    __int64 pTypeValue2;
    __int64 MappedBase;
    _DWORD Dst[16];
    char IsFull;
    char FoundFlag;
    ULONG CurrentOffset;
    __int64 pOutputEntry;
    __int64 pOutputBufferPtr;
    int MainStride;
    int SubStride;
    char KernelByte;

    pBuffer = ExAlloc(PagedPool, 0x3000);
    if (!pBuffer)
        return 0;

    memset(pBuffer, 0, 0x3000);
    pOutputBufferPtr = (__int64)pOutputBuffer;
    CurrentOffset = 552 * *pOutputBuffer + 560;
    pOutputEntry = (__int64)&pOutputBuffer[138 * *pOutputBuffer + 2];

    pValidateFunc = GtRead(0x41DE);
    pCheckFunc = GtRead(0x41E4);
    pCheckFlagFunc = GtRead(0x41E1);
    pTargetType = GtRead(0x27);
    pNtoskrnlBase = GtRead(3);
    pLookupFunc = GtRead(2);
    pRangeStart = GtRead(0x41DB);
    pRangeEnd = GtRead(0x4160);

    if (!pLookupFunc || !pNtoskrnlBase || !pRangeStart || !pRangeEnd || !pValidateFunc || !pCheckFunc || !pCheckFlagFunc || !pTargetType || CurrentOffset >= OutputSize || pTargetType == -1)
    {
        ExFree(pBuffer);
        return 0;
    }

    memset(Dst, 0, 0x40);
    {
        char *pCurrentThread = (char *)__readgsqword(0x188);
        KernelByte = pCurrentThread[pTargetType];
        pCurrentThread[pTargetType] = 0;
        ((void (__fastcall *)(_DWORD *, ULONG, UCHAR))pValidateFunc)(Dst, 0x40, 0);
        pCurrentThread[pTargetType] = KernelByte;
    }

    // Get virtual address range
    RangeStart = 0;
    RangeEnd = 0;
    pTypeValue = pLookupFunc;
    pTypeValue2 = pCheckFunc;
    GetKernelVirtualAddressRange((__int64)&RangeStart, (unsigned __int64 *)&RangeEnd, (unsigned __int64 *)pNtoskrnlBase);

    MappedBase = *(ULONG64 *)pRangeStart;
    FoundFlag = 0;
    IsFull = 0;
    CurrentAddr = RangeStart;

    while (CurrentAddr < RangeEnd)
    {
        if (FoundFlag)
            goto ProcessSubBlock;

        // Validate current address block
        if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(CurrentAddr) == 1 &&
            CallRegisteredCallback(CurrentAddr) == 1)
        {
            __int64 Offset = ((__int64 (__fastcall *)(__int64))pLookupFunc)(CurrentAddr);
            if (Offset && Offset < pNtoskrnlBase &&
                CmdStubAlwaysTrue(pValidateFunc, Offset, NULL, 0) == 1 &&
                ValidateEnumerationResult(pCheckFlagFunc, CurrentAddr, Offset) == 1)
            {
                FoundFlag = 1;
            }
        }

        if (!FoundFlag)
            goto NextBlock;

ProcessSubBlock:
        {
            __int64 SubAddr = CurrentAddr + 0x1000;
            FoundFlag = 0;
            MainStride = 0x1000;
            SubStride = 0xE80;

            if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(SubAddr) == 1 &&
                CallRegisteredCallback(SubAddr) == 1)
            {
                __int64 SubOffset = ((__int64 (__fastcall *)(__int64))pLookupFunc)(SubAddr);
                if (SubOffset && SubOffset < pNtoskrnlBase &&
                    CmdStubAlwaysTrue(pValidateFunc, SubOffset, NULL, 0) == 1 &&
                    ValidateEnumerationResult(pCheckFlagFunc, SubAddr, SubOffset) == 1)
                {
                    MainStride = 0x2000;
                    SubStride = 0x1E80;
                    FoundFlag = 1;
                }
            }
        }

        // Validate main block
        if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(CurrentAddr) == 1 &&
            ((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(CurrentAddr + MainStride - 1) == 1)
        {
            memmove(pBuffer, (void *)CurrentAddr, MainStride);

            // Iterate through entries in block
            int EntryOffset = 0;
            while (EntryOffset <= SubStride)
            {
                if (GtRead(0x914) >= 0x1DB0)
                {
                    char Flag = (char)CheckObjectTypeFlag((__int64)((char *)pBuffer + EntryOffset));
                    if (Flag != GtRead(0x81E))
                        goto NextEntry;
                }
                else
                {
                    if (*(ULONG64 *)((char *)pBuffer + EntryOffset + 0x10) != MappedBase)
                        goto NextEntry;
                }

                // Enumerate driver object table
                if (EnumerateDriverObjectTable((__int64)((char *)pBuffer + EntryOffset + 0x30), (__int64)((char *)pBuffer + EntryOffset + 0x30)) == 1)
                {
                    if (ValidateDriverObjectAddress((__int64)((char *)pBuffer + EntryOffset + 0x30), (__int64)((char *)pBuffer + EntryOffset + 0x30), 0, pOutputBuffer, OutputSize, pOutputEntry) == 1)
                    {
                        ++*pOutputBuffer;
                        CurrentOffset += 552;
                        pOutputEntry += 552;
                        if (CurrentOffset >= OutputSize)
                        {
                            IsFull = 1;
                            break;
                        }
                    }
                }

NextEntry:
                EntryOffset += 8;
                if (EntryOffset > 0x180)
                    break;
            }
        }

        if (IsFull)
            break;

NextBlock:
        CurrentAddr += 0x1000;
    }

    ExFree(pBuffer);
    return 0;
}
__int64 EnumerateKernelModules(unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    PVOID pBuffer;
    __int64 pValidateFunc;
    __int64 pLookupFunc;
    __int64 pCheckFunc;
    __int64 pCheckFlagFunc;
    __int64 pNtoskrnlBase;

    pBuffer = ExAlloc(PagedPool, 0x3000);
    if (!pBuffer)
        return 0;

    memset(pBuffer, 0, 0x3000);

    __int64 pOutputEntry = (__int64)&pOutputBuffer[138 * *pOutputBuffer + 2];
    unsigned int CurrentOffset = 552 * *pOutputBuffer + 560;

    pValidateFunc = GtRead(0x41DE);
    pLookupFunc = GtRead(0x41E4);
    pCheckFunc = GtRead(0x41E1);
    pCheckFlagFunc = GtRead(0x27);
    pNtoskrnlBase = GtRead(3);
    __int64 pLookupFunc2 = GtRead(2);
    __int64 pRangeStart = GtRead(0x4172);
    __int64 pRangeEnd = GtRead(0x4160);
    __int64 pTypeValue = GtRead(0x4163);
    __int64 pTypeCheck = GtRead(0x41DB);

    if (!pLookupFunc2 || !pNtoskrnlBase || !pRangeStart || !pRangeEnd || !pValidateFunc || !pCheckFunc || !pCheckFlagFunc || !pTypeValue || !pTypeCheck || pNtoskrnlBase == -1 || CurrentOffset >= OutputSize)
    {
        ExFree(pBuffer);
        return 0;
    }

    _DWORD Dst[16];
    memset(Dst, 0, 0x40);
    {
        char *pCurrentThread = (char *)__readgsqword(0x188);
        char KernelByte = pCurrentThread[pNtoskrnlBase];
        pCurrentThread[pNtoskrnlBase] = 0;
        ((void (__fastcall *)(_DWORD *, ULONG, UCHAR))pLookupFunc2)(Dst, 0x40, 0);
        pCurrentThread[pNtoskrnlBase] = KernelByte;
    }

    __int64 RangeStart = 0, RangeEndVal = 0, RangeSize = 0;
    FindHalDllInDriverList(pOutputBuffer, OutputSize, (_QWORD *)&RangeStart, (_DWORD *)&RangeSize);
    GetKernelVirtualAddressRange((__int64)&RangeStart, (unsigned __int64 *)&RangeEndVal, (unsigned __int64 *)0);

    __int64 MappedBase = *(ULONG64 *)pTypeCheck;
    char FoundFlag = 0;
    char IsFull = 0;
    int MainStride = 0x1000;
    int SubStride = 0xE80;
    __int64 CurrentAddr = RangeStart;

    while (CurrentAddr < RangeEndVal)
    {
        if (FoundFlag)
            goto ProcessSubModule;

        if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(CurrentAddr) == 1 &&
            CallRegisteredCallback(CurrentAddr) == 1)
        {
            __int64 Offset = ((__int64 (__fastcall *)(__int64))pLookupFunc2)(CurrentAddr);
            if (Offset && Offset < RangeSize &&
                CmdStubAlwaysTrue(pValidateFunc, Offset, NULL, 0) == 1 &&
                ValidateEnumerationResult(pCheckFlagFunc, CurrentAddr, Offset) == 1)
            {
                FoundFlag = 1;
            }
        }

        if (!FoundFlag)
            goto NextBlock2;

ProcessSubModule:
        {
            FoundFlag = 0;
            __int64 SubAddr = CurrentAddr + 0x1000;

            if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(SubAddr) == 1 &&
                CallRegisteredCallback(SubAddr) == 1)
            {
                __int64 SubOffset = ((__int64 (__fastcall *)(__int64))pLookupFunc2)(SubAddr);
                if (SubOffset && SubOffset < RangeSize &&
                    CmdStubAlwaysTrue(pValidateFunc, SubOffset, NULL, 0) == 1 &&
                    ValidateEnumerationResult(pCheckFlagFunc, SubAddr, SubOffset) == 1)
                {
                    MainStride = 0x2000;
                    SubStride = 0x1E80;
                    FoundFlag = 1;
                }
            }
        }

        if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(CurrentAddr) == 1 &&
            ((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(CurrentAddr + 0x1000 - 1) == 1)
        {
            memmove(pBuffer, (void *)CurrentAddr, 0x1000);

            __int64 EntryOffset = 0;
            while (EntryOffset <= SubStride)
            {
                if (GtRead(0x914) >= 0x1DB0)
                {
                    UCHAR Flag = (UCHAR)CheckObjectTypeFlag((__int64)((char *)pBuffer + EntryOffset));
                    if (Flag != (UCHAR)GtRead(0x81E))
                        goto NextBlockEntry;
                }
                else
                {
                    if (*(ULONG64 *)((char *)pBuffer + EntryOffset + 0x10) != MappedBase)
                        goto NextBlockEntry;
                }

                // Check module structure
                __int64 pModuleStruct = *(ULONG64 *)((char *)pBuffer + EntryOffset + 0x38);
                if ((ULONG64)pModuleStruct > *(ULONG64 *)pRangeEnd)
                {
                    if (((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(pModuleStruct - 0x2F) == 1 &&
                        ((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(pModuleStruct) == 1 &&
                        ((unsigned __int8 (__fastcall *)(__int64))pValidateFunc)(pModuleStruct + 0x14F) == 1)
                    {
                        __int64 pModuleBase = pModuleStruct - 0x30;
                        if (GtRead(0x914) >= 0x1DB0)
                        {
                            UCHAR TypeFlag = CheckObjectTypeFlagWrapper(pModuleBase);
                            if (TypeFlag != (UCHAR)GtRead(0x81D))
                                goto NextBlockEntry;
                        }
                        else
                        {
                            if (*(ULONG64 *)(pModuleBase + 0x10) != *(ULONG64 *)pTypeValue)
                                goto NextBlockEntry;
                        }

                        // Module validated, add to output
                        if (ValidateDriverObjectAddress(pModuleStruct, pModuleStruct, 0, pOutputBuffer, OutputSize, pOutputEntry) == 1)
                        {
                            ++*pOutputBuffer;
                            CurrentOffset += 552;
                            pOutputEntry += 552;
                            if (CurrentOffset >= OutputSize)
                            {
                                IsFull = 1;
                                break;
                            }
                        }
                    }
                }

NextBlockEntry:
                EntryOffset += 8;
                if (EntryOffset > 0x180)
                    break;
            }
        }

        if (IsFull)
            break;

NextBlock2:
        CurrentAddr += 0x1000;
    }

    ExFree(pBuffer);
    return 0;
}
void EnumerateDriverFiles(_DWORD *pOutputBuffer)
{
    WORD *pSystemRoot;
    WORD *pSystem32Path;
    WORD *pDriversPath;
    void *pDriversPathCopy;
    WORD *pTempBuffer;
    _DWORD *pOutputEntry;
    __int64 EntryCount;
    WORD *pNameBuffer;

    pSystemRoot = InitSystemPath();
    pSystem32Path = BuildSystem32Path();
    pDriversPath = BuildDriversPath();
    pDriversPathCopy = pDriversPath;

    if (!pSystemRoot || !pSystem32Path || !pDriversPath)
        goto Cleanup;

    _DWORD EncodedPrefix[3];
    EncodedPrefix[0] = 4456540;
    EncodedPrefix[1] = 7733349;
    EncodedPrefix[2] = 6488169;
    __int64 ExtraValue = 6029413;

    pTempBuffer = (WORD *)ExAlloc(PagedPool, 0x400);
    if (!pTempBuffer)
        goto Cleanup;

    pOutputEntry = pOutputBuffer + 2;
    if (*pOutputBuffer)
    {
        EntryCount = (unsigned int)*pOutputBuffer;
        pNameBuffer = (WORD *)(pOutputBuffer + 11);

        do
        {
            pNameBuffer[255] = 0;
            if (*pNameBuffer)
            {
                WORD *pLastSlash = WStringFindChar(pNameBuffer, L'\\');
                if (pLastSlash)
                {
                    WORD *pColon = WStringFindChar(pNameBuffer, L':');
                    if (pColon)
                    {
                        if (pColon[1] == L'\\' && pNameBuffer != pColon)
                        {
                            WStringCopy(pTempBuffer, pColon - 1);
                            WStringCopy(pNameBuffer, pTempBuffer);
                        }
                    }
                    else
                    {
                        if (!StringCompare3Way((__int64)EncodedPrefix, pNameBuffer, 8))
                        {
                            WORD DeviceName[2];
                            unsigned int DeviceNameLen;
                            if (BuildDevicePathFromObjects(pNameBuffer, DeviceName, (int *)&DeviceNameLen) == 1)
                            {
                                pTempBuffer[0] = DeviceName[0];
                                pTempBuffer[1] = L':';
                                WStringCopyN(pTempBuffer + 2, (__int64)pOutputEntry + 2 * DeviceNameLen + 36, 0xFE);
                                pTempBuffer[255] = 0;
                                WStringCopy(pNameBuffer, pTempBuffer);
                            }
                            goto DoneEntry;
                        }

                        if (pLastSlash[1])
                        {
                            WORD *pSlash2 = WStringFindChar(pLastSlash + 1, L'\\');
                            if (pSlash2)
                            {
                                WStringCopyN(pTempBuffer, (__int64)pSlash2, 0x100);
                                pTempBuffer[255] = 0;
                                WStringCopyN(pNameBuffer, (__int64)pSystemRoot, 0x100);
                                pNameBuffer[255] = 0;
                                if (GetStringLength(pNameBuffer) < 0xFF)
                                {
                                    int CurrentLen = (int)GetStringLength(pNameBuffer);
                                    WStringConcat(pNameBuffer, pTempBuffer, 255 - CurrentLen);
                                    pNameBuffer[255] = 0;
                                }
                            }
                            else if (*pNameBuffer != L'\\')
                            {
                                pTempBuffer[0] = L'\\';
                                WStringCopyN(pTempBuffer + 1, (__int64)pNameBuffer, 0xFF);
                                pTempBuffer[255] = 0;
                                WStringCopyN(pNameBuffer, (__int64)pSystemRoot, 0x100);
                                pNameBuffer[255] = 0;
                                if (GetStringLength(pNameBuffer) < 0xFF)
                                {
                                    int CurrentLen = (int)GetStringLength(pNameBuffer);
                                    WStringConcat(pNameBuffer, pTempBuffer, 255 - CurrentLen);
                                    pNameBuffer[255] = 0;
                                }
                            }
                        }
                    }
                }
                else
                {
                    // No backslash - try drivers path, then system32
                    pTempBuffer[0] = 0x3F0; // encoded prefix
                    pTempBuffer[1] = 0x5BFF;
                    WStringCopyN(pTempBuffer + 4, (__int64)pDriversPathCopy, 0xFC);
                    pTempBuffer[255] = 0;

                    if (GetStringLength(pTempBuffer) < 0xFF)
                    {
                        int StrLen1 = (int)GetStringLength(pTempBuffer);
                        WStringConcat(pTempBuffer, pNameBuffer, 255 - StrLen1);
                        pTempBuffer[255] = 0;

                        if (!OpenDriverFile(pTempBuffer))
                        {
                            WStringCopyN(pTempBuffer + 4, (__int64)pSystem32Path, 0xFC);
                            pTempBuffer[255] = 0;
                            if (GetStringLength(pTempBuffer) < 0xFF)
                            {
                                int StrLen2 = (int)GetStringLength(pTempBuffer);
                                WStringConcat(pTempBuffer, (WORD *)GtRead(GtPathBuffer00), 255 - StrLen2);
                                int StrLen3 = (int)GetStringLength(pTempBuffer);
                                WStringConcat(pTempBuffer, pNameBuffer, 255 - StrLen3);
                                pTempBuffer[255] = 0;
                            }
                        }
                    }
                    WStringCopyN(pNameBuffer, (__int64)(pTempBuffer + 4), 0x100);
                }
            }

DoneEntry:
            pOutputEntry += 138;
            pNameBuffer += 276;
            --EntryCount;
        } while (EntryCount);
    }

    ExFree(pTempBuffer);

Cleanup:
    if (pSystemRoot)
        ExFree(pSystemRoot);
    if (pSystem32Path)
        ExFree(pSystem32Path);
    if (pDriversPathCopy)
        ExFree(pDriversPathCopy);
}
__int64 FindPeExecutableSection(void)
{
    __int64 KernelBase = GtRead(GtEprocessField22);
    unsigned int KernelSize = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    __int64 result = GtRead(GtTotalSize | GtEprocessField16 | 0x400);

    if (!KernelBase || !KernelSize || !NtImageBase || !(_DWORD)result || (unsigned int)result >= KernelSize)
        return result;

    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int FieldValue = 0;
    __int64 EntryFlags = 0;
    __int64 EntryField2 = 0;
    int EntryCharacteristics = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    InitPESectionReadContext(
        KernelBase + (unsigned int)result,
        (ULONG)(KernelSize - (unsigned int)result),
        2, 0, -1, 0, 0,
        (__int64)&ReadContext);

    for (unsigned int SectionIndex = 0; SectionIndex < 0x14; SectionIndex++)
    {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        result = ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry);
        if ((_DWORD)result)
            break;

        int CalculatedSize = SectionSize + (int)CumulativeSize;
        CumulativeSize += SectionSize;

        if (*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1292 && EntryFlags == 0x40000)
        {
            if (FieldValue && EntryField2 == 64 && EntryCharacteristics == 1)
            {
                return GtWrite(
                    GtPeExecutableSectionBase,
                    NtImageBase + CalculatedSize + FieldValue - (unsigned int)KernelBase);
            }
        }
    }

    return result;
}
__int64 ScanFileForPeSectionInfo(void)
{
    __int64 KernelBase = GtRead(0x20);
    unsigned int KernelSize = (unsigned int)GtRead(0x21);
    __int64 NtImageBase = GtRead(4);
    __int64 NtImageSize = GtRead(0x177);
    int Result = -1;

    if (!KernelBase || !KernelSize || !NtImageBase || !NtImageSize)
        return Result;

    if (NtImageSize <= NtImageBase)
        return Result;

    unsigned int SizeDiff = (unsigned int)(NtImageSize - NtImageBase);
    if (SizeDiff >= KernelSize)
        return Result;

    if (NtImageBase + SizeDiff != NtImageSize)
        return Result;

    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    // ReadPESectionEntry 只填充前 0x120 字节，但本函数会访问到 +0x1A0 处，
    // 故缓冲须大于 0x120（原声明 [72] 恰为 0x120，会越界读到相邻栈变量）
    _DWORD SectionEntry[112];
    __int64 CumulativeSize = 0;
    char FoundMatch = 0;

    InitPESectionReadContext(
        NtImageBase + SizeDiff,
        (ULONG)KernelBase,
        (INT)(SizeDiff + KernelSize - (unsigned int)NtImageBase),
        2, 0, -1, 0, 0);

    for (unsigned int SectionIndex = 0; SectionIndex < 0x100; SectionIndex++)
    {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            break;

        // Read section fields from SectionEntry
        unsigned int SectionSize = *(unsigned int *)((char *)SectionEntry + 0x60);
        CumulativeSize += SectionSize;
        WORD SectionFlags = *(WORD *)((char *)SectionEntry + 0x1A0 + 6);

        if (SectionFlags == 0x4D7 && *(ULONG64 *)((char *)SectionEntry + 0xE8) == 0x20 &&
            *(_DWORD *)((char *)SectionEntry + 0xF0) == 2 &&
            *(ULONG64 *)((char *)SectionEntry + 0x120) == 0x20 &&
            *(_DWORD *)((char *)SectionEntry + 0x128) == 2)
        {
            FoundMatch = 1;
        }
        else if (FoundMatch == 1 && SectionFlags == 0x558 &&
                 (*(ULONG64 *)((char *)SectionEntry + 0xE8) & 0x4000000) != 0)
        {
            unsigned int FieldValue = *(unsigned int *)((char *)SectionEntry + 0xD0);
            if (FieldValue)
            {
                Result = FieldValue - (unsigned int)KernelBase + (int)CumulativeSize;
                if (Result > 0 && (unsigned int)Result < KernelSize)
                    return Result;
            }
        }
    }

    return Result;
}
char BuildDevicePathFromObjects(unsigned __int16 *pPath, WORD *pDriveLetter, int *pOffset)
{
    char Result = 0;
    void (__fastcall *pDecodeFunc)(_BYTE *, _DWORD *);
    int (__fastcall *pOpenKeyFunc)(__int64 *, __int64, int *);
    int (__fastcall *pQueryFunc)(__int64, int *, _QWORD);
    void (__fastcall *pCloseFunc)(__int64);

    pDecodeFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    pOpenKeyFunc = (int (__fastcall *)(__int64 *, __int64, int *))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField12);
    pQueryFunc = (int (__fastcall *)(__int64, int *, _QWORD))GtRead(GtTotalSize | GtObjectTypeField27 | GtDriverObject);
    pCloseFunc = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);

    if (!pDecodeFunc || !pOpenKeyFunc || !pQueryFunc || !pCloseFunc)
        return Result;

    _DWORD EncodedData[6];
    EncodedData[0] = 4456540;
    EncodedData[1] = 7536751;
    EncodedData[2] = 6619204;
    EncodedData[3] = 6881398;
    EncodedData[4] = 6619235;
    EncodedData[5] = 6029427;
    int ColonChar = 58;

    for (unsigned int DriveIndex = 0; DriveIndex < 26; DriveIndex++)
    {
        WORD DriveName = DriveIndex + 65;
        _BYTE DecodedBuffer[16];
        __int64 KeyHandle;
        __int64 ZeroStruct = 0;
        int ObjAttr = 48;
        _BYTE *DecodedPath = DecodedBuffer;
        int Flags = 576;

        pDecodeFunc(DecodedBuffer, EncodedData);
        if (pOpenKeyFunc(&KeyHandle, 0x80000000, &ObjAttr) >= 0)
        {
            int QueryResult = 34078720;
            void *pBuffer = ExAlloc(PagedPool, 0x208);
            if (pBuffer)
            {
                memset(pBuffer, 0, 0x208);
                if (pQueryFunc(KeyHandle, &QueryResult, 0) >= 0 &&
                    (QueryResult & 0xFFFE) > 0x10 &&
                    !StringCompare3Way((__int64)pBuffer, pPath, (unsigned __int16)QueryResult >> 1))
                {
                    Result = 1;
                    *pOffset = (unsigned __int16)QueryResult >> 1;
                    *pDriveLetter = DriveName;
                }
                ExFree(pBuffer);
            }
            pCloseFunc(KeyHandle);
        }

        if (Result == 1)
            break;
    }

    return Result;
}
__int64 ParseNtExportDirTable(
    __int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase,
    __int64 NtImageDelta, __int64 OutputEntry, unsigned int OutputEntrySize,
    _DWORD *pBytesWritten)
{
    *pBytesWritten = 0;
    __int64 PeOffset = *(int *)(ImageBase + 60);
    unsigned int ExportDirRva = *(unsigned int *)(PeOffset + ImageBase + 136);
    unsigned int ExportDirSize = *(unsigned int *)(PeOffset + ImageBase + 140);
    unsigned int ExportDirEnd = ExportDirSize + ExportDirRva;
    unsigned int ResultCount = 0;

    if (ExportDirRva >= ImageSize || ExportDirRva + 40 > (unsigned __int64)ImageSize ||
        ExportDirSize > ImageSize || ExportDirEnd > ImageSize)
        return 0;

    unsigned int NumOfNames = *(_DWORD *)(ExportDirRva + ImageBase + 20);
    unsigned int NumOfFunctions = *(_DWORD *)(ExportDirRva + ImageBase + 24);

    if (NumOfNames < NumOfFunctions || !NumOfNames)
        return 0;

    unsigned int AddressOfNamesRva = *(unsigned int *)(ExportDirRva + ImageBase + 32);
    if (AddressOfNamesRva < ExportDirRva)
        return 0;

    __int64 AddressOfNames = AddressOfNamesRva;
    unsigned __int64 NameTableBytes = 4LL * NumOfFunctions;
    if (NameTableBytes + AddressOfNamesRva > ExportDirEnd || NameTableBytes >= ExportDirSize)
        return 0;

    unsigned int AddressOfOrdinalsRva = *(unsigned int *)(ExportDirRva + ImageBase + 36);
    if (AddressOfOrdinalsRva < ExportDirRva)
        return 0;

    __int64 AddressOfOrdinals = AddressOfOrdinalsRva;
    if (AddressOfOrdinalsRva + 2 * (unsigned __int64)NumOfFunctions > ExportDirEnd)
        return 0;

    unsigned int AddressOfFuncsRva = *(unsigned int *)(ExportDirRva + ImageBase + 28);
    if (AddressOfFuncsRva < ExportDirRva)
        return 0;

    unsigned __int64 FuncTableBytes = 4LL * NumOfNames;
    if (FuncTableBytes + AddressOfFuncsRva > ExportDirEnd || FuncTableBytes >= ExportDirSize)
        return 0;

    unsigned int *pFuncTable = (unsigned int *)(AddressOfFuncsRva + ImageBase);
    unsigned __int16 *pOrdinalTable = (unsigned __int16 *)(AddressOfOrdinals + ImageBase);
    __int64 NameTableData = AddressOfNames + ImageBase;
    unsigned int RemainingSize = OutputEntrySize;
    unsigned int NameIndex = 0;

    do
    {
        if (RemainingSize >= 0x25E)
        {
            unsigned int FuncRva = pFuncTable[NameIndex];
            __int64 PESection = FindPESectionByRva(ImageBase, ImageSize, FuncRva);

            if (PESection && CheckExportEntryFlags((PUCHAR)PESection) &&
                FuncRva < ImageSize && (FuncRva < ExportDirRva || FuncRva >= ExportDirEnd))
            {
                _BYTE *ExportData = (_BYTE *)(FuncRva + ImageBase);
                _BYTE *NtExportData = (_BYTE *)(FuncRva + NtImageDelta);
                unsigned int AlignSize = CalcSectionAlignedSize(FuncRva + ImageBase, ImageBase + ImageSize);

                if (AlignSize)
                {
                    unsigned int ByteIndex = 0;
                    while (*ExportData == *NtExportData)
                    {
                        ByteIndex++;
                        ExportData++;
                        NtExportData++;
                        if (ByteIndex >= AlignSize)
                            goto SkipEntry;
                    }

                    unsigned int CmpLen = CompareExportNamePrefix(ExportData, NtExportData, ImageBase + ImageSize);
                    if (!CmpLen || CmpLen >= AlignSize || CmpLen >= 0x32)
                        goto SkipEntry;

                    if (CmpLen >= 5)
                    {
                        unsigned int ZeroIdx1 = 0;
                        _BYTE *pCheck1 = ExportData;
                        while (!*pCheck1)
                        {
                            ZeroIdx1++;
                            pCheck1++;
                            if (ZeroIdx1 >= CmpLen)
                                goto SkipEntry;
                        }

                        unsigned int ZeroIdx2 = 0;
                        _BYTE *pCheck2 = NtExportData;
                        while (!*pCheck2)
                        {
                            ZeroIdx2++;
                            pCheck2++;
                            if (ZeroIdx2 >= CmpLen)
                                goto SkipEntry;
                        }
                    }

                    if (ValidateZeroPage((__int64)NtExportData, NtImageDelta + ImageSize) ||
                        CheckExportNamePrefixCombined(ExportData, NtExportData, AlignSize))
                    {
SkipEntry:
                        RemainingSize = OutputEntrySize;
                    }
                    else
                    {
                        // Find function name
                        __int64 FuncNameAddr = 0;
                        unsigned int OrdinalIndex = 0;
                        if (NumOfFunctions)
                        {
                            unsigned __int16 *OrdTable = pOrdinalTable;
                            while (*OrdTable != NameIndex)
                            {
                                OrdinalIndex++;
                                OrdTable++;
                                if (OrdinalIndex >= NumOfFunctions)
                                    goto FoundName;
                            }
                            unsigned int NameEntryAddr = *(unsigned int *)(NameTableData + 4LL * OrdinalIndex);
                            if (NameEntryAddr >= ExportDirRva && NameEntryAddr < ExportDirEnd)
                                FuncNameAddr = ImageBase + NameEntryAddr;
                        }

FoundName:
                        unsigned int NewEntrySize = 2 * CmpLen + 604;
                        if (OutputEntrySize >= NewEntrySize)
                        {
                            *(_QWORD *)OutputEntry = (_QWORD)&NtExportData[NtImageBase - NtImageDelta];
                            *(_QWORD *)(OutputEntry + 8) = 0;
                            CalcSectionRangeSize(FuncRva + ImageBase, (unsigned __int64)ExportData);

                            if (ReturnFalseStub() == 1)
                                *(_QWORD *)(OutputEntry + 8) = 0;

                            *(_WORD *)(OutputEntry + 16) = 0;
                            __int64 ExportAddr = *(_QWORD *)(OutputEntry + 8);
                            if (ExportAddr)
                            {
                                _DWORD *pExport = FindExportByAddress(ExportAddr);
                                if (pExport)
                                {
                                    WStringCopyN((WORD *)(OutputEntry + 16), (__int64)pExport, 0x104);
                                    *(WORD *)(OutputEntry + 534) = 0;
                                }
                            }

                            *(UCHAR *)(OutputEntry + 536) = 0;
                            if (FuncNameAddr)
                            {
                                StringCopy((_BYTE *)(OutputEntry + 536), FuncNameAddr, 0x40);
                                *(UCHAR *)(OutputEntry + 599) = 0;
                            }

                            *(_DWORD *)(OutputEntry + 600) = CmpLen;
                            memmove((void *)(OutputEntry + 604), ExportData, CmpLen);
                            memmove((void *)(CmpLen + OutputEntry + 604), NtExportData, CmpLen);

                            ResultCount++;
                            *pBytesWritten += NewEntrySize;
                            OutputEntry += NewEntrySize;
                            RemainingSize = OutputEntrySize - NewEntrySize;
                            OutputEntrySize = RemainingSize;
                        }
                        else
                        {
                            RemainingSize = 1;
                            OutputEntrySize = 1;
                        }
                    }
                }
            }
        }
        NameIndex++;
    } while (NameIndex < NumOfNames);

    return ResultCount;
}
__int64 ParseExportEntriesDetailed(
    __int64 TableEntry, unsigned int EntryCount, __int64 ImageBase,
    unsigned int ImageSize, __int64 NtImageBase, __int64 NtImageDelta,
    __int64 OutputEntry, unsigned int OutputEntrySize, _DWORD *pBytesWritten,
    __int64 FilterTable, unsigned int FilterTableSize)
{
    *pBytesWritten = 0;
    unsigned int ResultCount = 0;

    if (!TableEntry || !EntryCount)
        return 0;

    unsigned int EntryIndex = 0;
    unsigned int RemainingSize = OutputEntrySize;

    while (EntryIndex < EntryCount)
    {
        if (RemainingSize < 0x25E)
        {
            EntryIndex++;
            continue;
        }

        unsigned int *pCurrentEntry = (unsigned int *)(TableEntry + 72 + 88 * EntryIndex);
        unsigned int ExportRva = *pCurrentEntry;

        if (!ExportRva || ExportRva >= ImageSize)
        {
            RemainingSize = OutputEntrySize;
            EntryIndex++;
            continue;
        }

        _BYTE *ExportData = (_BYTE *)(ExportRva + ImageBase);
        _BYTE *NtExportData = (_BYTE *)(ExportRva + NtImageDelta);
        unsigned int AlignedSize = CalcSectionAlignedSize(ExportRva + ImageBase, ImageBase + ImageSize);

        if (AlignedSize)
        {
            unsigned int ByteIndex = 0;
            while (*ExportData == *NtExportData)
            {
                ByteIndex++;
                ExportData++;
                NtExportData++;
                if (ByteIndex >= AlignedSize)
                    goto SkipEntry2;
            }

            unsigned int CmpLen = CompareExportNamePrefix(ExportData, NtExportData, ImageBase + ImageSize);
            if (!CmpLen || CmpLen >= AlignedSize)
                goto SkipEntry2;

            if (CmpLen < 0x32)
            {
                if (CmpLen >= 5)
                {
                    unsigned int ZeroIdx1 = 0;
                    _BYTE *pCheck1 = ExportData;
                    while (!*pCheck1)
                    {
                        ZeroIdx1++;
                        pCheck1++;
                        if (ZeroIdx1 >= CmpLen)
                            goto SkipEntry2;
                    }

                    unsigned int ZeroIdx2 = 0;
                    _BYTE *pCheck2 = NtExportData;
                    while (!*pCheck2)
                    {
                        ZeroIdx2++;
                        pCheck2++;
                        if (ZeroIdx2 >= CmpLen)
                            goto SkipEntry2;
                    }
                }

                if (!ValidateZeroPage((__int64)NtExportData, NtImageDelta + ImageSize) &&
                    !CheckExportNamePrefixWin10V2(ExportData, NtExportData, CmpLen) &&
                    !FindExportEntryByAddress(
                        (__int64)&NtExportData[NtImageBase - NtImageDelta],
                        FilterTable, FilterTableSize))
                {
                    unsigned int NewEntrySize = 2 * CmpLen + 604;
                    if (OutputEntrySize >= NewEntrySize)
                    {
                        *(_QWORD *)OutputEntry = (_QWORD)&NtExportData[NtImageBase - NtImageDelta];
                        *(_QWORD *)(OutputEntry + 8) = 0;
                        CalcSectionRangeSize((__int64)ExportData, (unsigned __int64)ExportData);

                        if (ReturnFalseStub() == 1)
                            *(_QWORD *)(OutputEntry + 8) = 0;

                        *(_WORD *)(OutputEntry + 16) = 0;
                        __int64 ExportAddr = *(_QWORD *)(OutputEntry + 8);
                        if (ExportAddr)
                        {
                            _DWORD *pExport = FindExportByAddress(ExportAddr);
                            if (pExport)
                            {
                                WStringCopyN((WORD *)(OutputEntry + 16), (__int64)pExport, 0x104);
                                *(WORD *)(OutputEntry + 534) = 0;
                            }
                        }

                        *(UCHAR *)(OutputEntry + 536) = 0;
                        __int64 ModuleEntry = 88 * EntryIndex + TableEntry + 4;
                        if (ModuleEntry)
                        {
                            StringCopy((_BYTE *)(OutputEntry + 536), ModuleEntry, 0x40);
                            *(UCHAR *)(OutputEntry + 599) = 0;
                        }

                        *(_DWORD *)(OutputEntry + 600) = CmpLen;
                        memmove((void *)(OutputEntry + 604), ExportData, CmpLen);
                        memmove((void *)(CmpLen + OutputEntry + 604), NtExportData, CmpLen);

                        *pBytesWritten += NewEntrySize;
                        ResultCount++;
                        OutputEntry += NewEntrySize;
                        RemainingSize = OutputEntrySize - NewEntrySize;
                        OutputEntrySize = RemainingSize;
                    }
                    else
                    {
                        RemainingSize = 1;
                        OutputEntrySize = 1;
                    }
                }
            }
        }

SkipEntry2:
        EntryIndex++;
    }

    return ResultCount;
}
__int64 ParseAndCompareExportEntries(
    __int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase,
    __int64 NtImageDelta, __int64 OutputEntry, unsigned int OutputEntrySize,
    __int64 FilterTable, unsigned int FilterTableSize)
{
    __int64 PeHeader = ImageBase + *(int *)(ImageBase + 60);
    unsigned int EntryCount = 0;
    unsigned int SectionCount = *(unsigned __int16 *)(PeHeader + 6);
    unsigned int ResultCount = 0;
    unsigned int RemainingSize = OutputEntrySize;

    if (!SectionCount)
        return 0;

    __int64 SectionEntry = PeHeader + 24;
    unsigned int SectionIndex = 0;

    while (SectionIndex < SectionCount)
    {
        if (RemainingSize < 0x25E)
            return ResultCount;

        if ((unsigned __int8)GetExportEntrySignBit((PUCHAR)SectionEntry) ||
            (unsigned __int8)IsExportForwarder((PUCHAR)SectionEntry))
        {
            goto NextSection;
        }

        unsigned int ExportRva = *(_DWORD *)(SectionEntry + 8);
        unsigned int ExportSize = *(_DWORD *)(SectionEntry + 12);
        unsigned int DataDirSize = *(_DWORD *)(PeHeader + 236);
        unsigned int DataDirRva = *(_DWORD *)(PeHeader + 232);

        if (ExportSize == DataDirSize)
        {
            if (DataDirSize >= ExportRva)
                goto NextSection;
            ExportSize = DataDirSize + (unsigned int)ExportSize;
            ExportRva -= DataDirSize;
        }

        _BYTE *ExportEnd = (_BYTE *)(ExportSize + NtImageDelta);
        _BYTE *ExportData = (_BYTE *)(ImageBase + ExportSize + ExportRva);
        _BYTE *ExportEnd2 = (_BYTE *)(ExportSize + ImageBase);

        if ((unsigned __int64)ExportEnd2 >= (unsigned __int64)ExportData)
            goto NextSection;

        unsigned int CurrentSize = ResultCount;

        while (RemainingSize >= 0x25E)
        {
            if ((unsigned __int64)ExportEnd2 >= (unsigned __int64)ExportData)
                break;

            unsigned int CmpLen = 0;
            if (*ExportEnd != *ExportEnd2)
            {
                CmpLen = CompareExportNamePrefix(ExportEnd2, ExportEnd, (unsigned __int64)ExportData);
                if (CmpLen - 1 <= 0x30)
                {
                    if (CmpLen >= 5)
                    {
                        unsigned int ZeroIdx1 = 0;
                        _BYTE *pCheck1 = ExportEnd2;
                        while (!*pCheck1)
                        {
                            ZeroIdx1++;
                            pCheck1++;
                            if (ZeroIdx1 >= CmpLen)
                                goto SkipCompare;
                        }

                        unsigned int ZeroIdx2 = 0;
                        _BYTE *pCheck2 = ExportEnd;
                        while (!*pCheck2)
                        {
                            ZeroIdx2++;
                            pCheck2++;
                            if (ZeroIdx2 >= CmpLen)
                                goto SkipCompare;
                        }
                    }

                    if (!ValidateZeroPage((__int64)ExportEnd, NtImageDelta + ImageSize) &&
                        !CheckExportNamePrefixCombined(ExportEnd2, ExportEnd, CmpLen) &&
                        !FindExportEntryByAddress(
                            (__int64)&ExportEnd[NtImageBase - NtImageDelta],
                            FilterTable, FilterTableSize))
                    {
                        unsigned int NewEntrySize = 2 * CmpLen + 604;
                        if (OutputEntrySize >= NewEntrySize)
                        {
                            *(_QWORD *)OutputEntry = (_QWORD)&ExportEnd[NtImageBase - NtImageDelta];
                            *(_QWORD *)(OutputEntry + 8) = 0;
                            if (ReturnFalseStub() == 1)
                                *(_QWORD *)(OutputEntry + 8) = 0;

                            *(_WORD *)(OutputEntry + 16) = 0;
                            __int64 ExportAddr = *(_QWORD *)(OutputEntry + 8);
                            if (ExportAddr)
                            {
                                _DWORD *pExport = FindExportByAddress(ExportAddr);
                                if (pExport)
                                {
                                    WStringCopyN((WORD *)(OutputEntry + 16), (__int64)pExport, 0x104);
                                    *(WORD *)(OutputEntry + 534) = 0;
                                }
                            }

                            *(UCHAR *)(OutputEntry + 536) = 0;
                            *(_DWORD *)(OutputEntry + 600) = CmpLen;
                            memmove((void *)(OutputEntry + 604), ExportEnd2, CmpLen);
                            memmove((void *)(CmpLen + OutputEntry + 604), ExportEnd, CmpLen);

                            RemainingSize = OutputEntrySize - NewEntrySize;
                            OutputEntry += NewEntrySize;
                            CurrentSize++;
                            OutputEntrySize = RemainingSize;
                        }
                        else
                        {
                            RemainingSize = 1;
                            OutputEntrySize = 1;
                        }
                    }
                }
            }

            if (!CmpLen)
                CmpLen = 1;

            ExportEnd2 += CmpLen;
            ExportEnd += CmpLen;
        }

        ResultCount = CurrentSize;

SkipCompare:
NextSection:
        SectionEntry += 40;
        SectionIndex++;
    }

    return ResultCount;
}
__int64 ParseNtExportAuxData(
    __int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase,
    unsigned int NtImageDelta, __int64 OutputEntry, unsigned int OutputEntrySize,
    _DWORD *pBytesWritten)
{
    *pBytesWritten = 0;
    unsigned int ResultCount = 0;

    // 两个待处理的模块类型与模块基址（全局表索引），按迭代索引取用
    unsigned int ModuleTypeArray[2];
    ModuleTypeArray[0] = (unsigned int)GtRead(0x2B3);
    ModuleTypeArray[1] = (unsigned int)GtRead(0x339);

    ULONG64 ModuleBaseArray[2];
    ModuleBaseArray[0] = GtRead(0x2AA);
    ModuleBaseArray[1] = GtRead(0x33C);

    // 两个待比对字符串："pIofCompleteRequest" 与 "pIofCallDriver"（小端 dword 编码）
    char CompareString1[20]; // "pIofCompleteRequest\0"
    *(_DWORD *)&CompareString1[0]  = 0x666F4970; // "pIof"
    *(_DWORD *)&CompareString1[4]  = 0x706D6F43; // "Comp"
    *(_DWORD *)&CompareString1[8]  = 0x6574656C; // "lete"
    *(_DWORD *)&CompareString1[12] = 0x75716552; // "Requ"
    *(_DWORD *)&CompareString1[16] = 0x747365;   // "est"
    CompareString1[18] = 0;

    char CompareString2[20]; // "pIofCallDriver\0"
    *(_DWORD *)&CompareString2[0]  = 0x666F4970; // "pIof"
    *(_DWORD *)&CompareString2[4]  = 0x6C6C6143; // "Call"
    *(_DWORD *)&CompareString2[8]  = 0x76697244; // "Driv"
    *(_WORD  *)&CompareString2[12] = 0x7265;     // "er"
    CompareString2[14] = 0;

    char *pCompareString[2];
    pCompareString[0] = CompareString1;
    pCompareString[1] = CompareString2;

    __int64 SearchEnd = ImageBase + ImageSize;
    __int64 pOutputPtr = OutputEntry + 8;
    unsigned int Index = 0;

    for (Index = 0; Index < 2; Index++)
    {
        if (OutputEntrySize < 0x25E)
            continue;

        unsigned int ModuleType = ModuleTypeArray[Index];
        if (!ModuleType || ModuleType >= ImageSize)
            continue;

        if (*(ULONG64 *)(ImageBase + ModuleType) == ModuleBaseArray[Index])
            continue;

        if (*(ULONG64 *)(ImageBase + ModuleType) == 0)
            continue;

        if (ValidateZeroPage(ImageBase + ModuleType, SearchEnd))
            continue;

        if (OutputEntrySize < 0x26C)
        {
            OutputEntrySize = 1; // 空间不足，下一轮条件使循环退出
            continue;
        }

        // 计算相对 NtImageDelta 的偏移
        __int64 Delta = ImageBase + ModuleType - NtImageDelta;
        *(_QWORD *)(pOutputPtr - 8) = Delta + NtImageBase;
        *(_QWORD *)pOutputPtr = *(ULONG64 *)(ImageBase + ModuleType);
        *(WORD *)(pOutputPtr + 8) = 0;

        if (*(_QWORD *)pOutputPtr)
        {
            _DWORD *pExport = FindExportByAddress(*(_QWORD *)pOutputPtr);
            if (pExport)
            {
                WStringCopyN((WORD *)(pOutputPtr + 8), (__int64)pExport, 0x104);
                *(WORD *)(pOutputPtr + 0x20E) = 0;
            }
        }

        *(UCHAR *)(pOutputPtr + 0x210) = 0;

        // 复制对应比对的字符串（"pIofCompleteRequest" / "pIofCallDriver"）
        if (pCompareString[Index])
        {
            StringCopy((_BYTE *)(pOutputPtr + 0x210), (__int64)pCompareString[Index], 0x40);
            *(UCHAR *)(pOutputPtr + 0x24F) = 0;
        }

        *(_DWORD *)(pOutputPtr + 0x250) = 8;
        *(ULONG64 *)(pOutputPtr + 0x254) = ModuleBaseArray[Index];
        *(ULONG64 *)(pOutputPtr + 0x25C) = *(ULONG64 *)(ImageBase + ModuleType);

        *pBytesWritten += 0x26C;
        ResultCount++;
        pOutputPtr += 0x26C;
        OutputEntrySize -= 0x26C;
    }

    return ResultCount;
}
__int64 ParseExportDirAndBuildIndex(
    __int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase,
    __int64 NtImageDelta, __int64 OutputTable, unsigned int OutputSize)
{
    unsigned int ResultCount = 0;
    unsigned int RegRefCount = (unsigned int)GtRead(GtWin32kServiceTableVersion);

    __int64 PeOffset = *(int *)(ImageBase + 60);
    unsigned int ExportDirRva = *(unsigned int *)(PeOffset + ImageBase + 136);
    unsigned int ExportDirSize = *(unsigned int *)(PeOffset + ImageBase + 140);
    unsigned int ExportDirEnd = ExportDirSize + ExportDirRva;

    if (ExportDirRva >= ImageSize || ExportDirRva + 40 > (unsigned __int64)ImageSize ||
        ExportDirSize > ImageSize || ExportDirEnd > ImageSize)
        return 0;

    unsigned int NumOfFunctions = *(_DWORD *)(ExportDirRva + ImageBase + 24);
    unsigned int AddressOfFuncs = *(unsigned int *)(ExportDirRva + ImageBase + 28);
    unsigned int NumOfNames = *(_DWORD *)(ExportDirRva + ImageBase + 20);

    unsigned int *pFuncTable = (unsigned int *)(AddressOfFuncs + NtImageDelta);

    if (NumOfNames < NumOfFunctions || !NumOfNames)
        return 0;

    unsigned int AddressOfNames = *(unsigned int *)(ExportDirRva + ImageBase + 32);
    if (AddressOfNames < ExportDirRva)
        return 0;

    unsigned __int64 NameTableSize = 4LL * NumOfFunctions;
    if (NameTableSize + AddressOfNames > ExportDirEnd || NameTableSize >= ExportDirSize)
        return 0;

    unsigned int OrdinalTableRva = *(unsigned int *)(ExportDirRva + ImageBase + 36);
    if (OrdinalTableRva < ExportDirRva)
        return 0;

    if (OrdinalTableRva + 2 * (unsigned __int64)NumOfFunctions > ExportDirEnd)
        return 0;

    if (AddressOfFuncs < ExportDirRva)
        return 0;

    unsigned __int64 FuncTableSize = 4LL * NumOfNames;
    if (FuncTableSize + AddressOfFuncs > ExportDirEnd || FuncTableSize >= ExportDirSize)
        return 0;

    __int64 NameTableData = ImageBase + AddressOfNames;
    unsigned __int16 *pOrdinalTable = (unsigned __int16 *)(OrdinalTableRva + ImageBase);
    __int64 FuncTableData = ImageBase + AddressOfFuncs;

    if (RegRefCount <= 2)
        ParseExportSectionAndIndex(ImageBase, ImageSize, RegRefCount);

    unsigned int NameIndex = 0;
    __int64 OutEntryPtr = OutputTable + 12;

    do
    {
        if (OutputSize >= 0x26C)
        {
            unsigned int ExportRva = *(unsigned int *)((char *)pFuncTable + (FuncTableData - (__int64)pFuncTable));
            if (ExportRva < ImageSize && (ExportRva < ExportDirRva || ExportRva >= ExportDirEnd))
            {
                unsigned int FuncRva = *pFuncTable;
                if (FuncRva && ExportRva != FuncRva)
                {
                    // Find ordinal
                    __int64 OrdinalAddr = 0;
                    unsigned int OrdinalIndex = 0;
                    if (NumOfFunctions)
                    {
                        unsigned __int16 *pOrdTable = pOrdinalTable;
                        while (*pOrdTable != NameIndex)
                        {
                            OrdinalIndex++;
                            pOrdTable++;
                            if (OrdinalIndex >= NumOfFunctions)
                                goto FoundOrdinal;
                        }
                        unsigned int ExportAddr = *(unsigned int *)(NameTableData + 4LL * OrdinalIndex);
                        if (ExportAddr >= ExportDirRva && ExportAddr < ExportDirEnd)
                            OrdinalAddr = ImageBase + ExportAddr;
                    }

FoundOrdinal:
                    *(_DWORD *)(OutEntryPtr - 4) = ExportRva;
                    *(_DWORD *)OutEntryPtr = FuncRva;
                    *(_QWORD *)(OutEntryPtr - 12) = (_QWORD)((char *)pFuncTable + 4LL * NameIndex - NtImageDelta + NtImageBase);
                    *(_QWORD *)(OutEntryPtr + 4) = NtImageBase + ExportRva;
                    *(_QWORD *)(OutEntryPtr + 12) = NtImageBase + FuncRva;
                    *(UCHAR *)(OutEntryPtr + 20) = 0;

                    if (OrdinalAddr)
                    {
                        StringCopy((_BYTE *)(OutEntryPtr + 20), OrdinalAddr, 0x40);
                        *(UCHAR *)(OutEntryPtr + 83) = 0;
                    }

                    *(_DWORD *)(OutEntryPtr + 84) = NameIndex + *(_DWORD *)(ExportDirRva + ImageBase + 16);
                    *(WORD *)(OutEntryPtr + 88) = 0;

                    _DWORD *pExport = FindExportByAddress(*(_QWORD *)(OutEntryPtr + 12));
                    if (pExport)
                    {
                        WStringCopyN((WORD *)(OutEntryPtr + 88), (__int64)pExport, 0x104);
                        *(WORD *)(OutEntryPtr + 606) = 0;
                    }

                    OutputSize -= 620;
                    OutEntryPtr += 620;
                    ResultCount++;
                }
            }
        }
        pFuncTable++;
        NameIndex++;
    } while (NameIndex < NumOfNames);

    return ResultCount;
}
__int64 ParseExportDirectoryEntries(
    __int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase,
    __int64 NtImageDelta, unsigned __int64 OutputBuffer, unsigned int OutputSize)
{
    unsigned int ResultCount = 0;
    void *pModuleFileBuffer = 0;

    GtRead(GtWin32kServiceTableVersion);
    __int64 PeOffset = *(int *)(ImageBase + 60);
    unsigned int DataDirRva = *(unsigned int *)(PeOffset + ImageBase + 144);
    unsigned int DataDirSize = *(_DWORD *)(PeOffset + ImageBase + 148);

    if (DataDirRva >= ImageSize)
        return 0;

    if (DataDirRva + 20 > (unsigned __int64)ImageSize || DataDirSize > ImageSize ||
        DataDirSize + DataDirRva > ImageSize)
        return 0;

    int RemainingBytes = ImageSize - DataDirRva;
    if ((unsigned __int64)RemainingBytes < 0x14)
        return 0;

    unsigned int *pModuleEntry = (unsigned int *)(DataDirRva + ImageBase + 16);
    unsigned int SafeImageSize = ImageSize;

    do
    {
        unsigned int ModuleNameRva = *pModuleEntry;
        if (!ModuleNameRva)
            break;
        if (OutputSize < 0x2A8)
            break;
        if (ModuleNameRva >= ImageSize)
            break;
        if (ModuleNameRva + 8 > (unsigned __int64)ImageSize)
            break;

        unsigned int ModuleNamePtr = *(pModuleEntry - 1);
        if (ModuleNamePtr > ImageSize)
            break;

        const char *ModuleName = (const char *)(ImageBase + ModuleNamePtr);
        char ReadFileResult = 0;
        __int64 ExportDirBase;
        unsigned int ExportDirCount;
        char ModuleType = ClassifyModuleTypeHalOrNt(ModuleName, &ExportDirBase, &ExportDirCount);

        if (ModuleType == 1)
        {
            ReadFileResult = ReadModuleFileToBuffer(ModuleName, &pModuleFileBuffer, &ExportDirCount, &ExportDirBase);
        }

        if (!ModuleType || ReadFileResult == 1)
        {
            unsigned int ImportTableRva = *pModuleEntry;
            int ImportOffset = SafeImageSize - ImportTableRva;
            __int64 *pImportDesc = (__int64 *)(ImageBase + ImportTableRva);

            if ((unsigned __int64)ImportOffset >= 8)
            {
                __int64 *pImportThunk = (__int64 *)(NtImageDelta + ImportTableRva);
                __int64 BaseDelta = NtImageBase - NtImageDelta;

                do
                {
                    __int64 ThunkData = *pImportDesc;
                    if (!ThunkData || OutputSize < 0x2A8)
                        break;

                    if (ThunkData > 0 && (unsigned __int64)ThunkData < SafeImageSize && (unsigned __int64)(ThunkData + 4) < SafeImageSize)
                    {
                        __int64 ThunkValue = ThunkData + ImageBase + 2;
                        unsigned int ExportOrdinal;

                        char FoundResult;
                        if (ModuleType)
                            FoundResult = LookupExportByName((PUCHAR)pModuleFileBuffer, ExportDirCount, (PCHAR)ThunkValue, &ExportOrdinal);
                        else
                            FoundResult = BtreeSearchByKey((unsigned __int8 *)(ThunkData + ImageBase + 2), &ExportOrdinal, ExportDirCount);

                        if (FoundResult == 1)
                        {
                            __int64 ExportEntryAddr = ExportDirBase + ExportOrdinal;
                            if (*pImportThunk != ExportEntryAddr && *pImportThunk)
                            {
                                *(_QWORD *)(OutputBuffer + 12) = ExportEntryAddr;
                                *(_DWORD *)OutputBuffer = 8;
                                *(_QWORD *)(OutputBuffer + 4) = (_QWORD)((char *)pImportThunk + BaseDelta);
                                *(_QWORD *)(OutputBuffer + 20) = *pImportThunk;
                                StringCopy((_BYTE *)(OutputBuffer + 28), (__int64)ModuleName, 0x40);
                                *(UCHAR *)(OutputBuffer + 91) = 0;
                                StringCopy((_BYTE *)(OutputBuffer + 92), ThunkValue, 0x40);
                                *(UCHAR *)(OutputBuffer + 155) = 0;
                                *(_DWORD *)(OutputBuffer + 156) = 0;
                                *(WORD *)(OutputBuffer + 160) = 0;

                                _DWORD *pExport = FindExportByAddress(*(_QWORD *)(OutputBuffer + 20));
                                if (pExport)
                                {
                                    WStringCopyN((WORD *)(OutputBuffer + 160), (__int64)pExport, 0x104);
                                    *(WORD *)(OutputBuffer + 678) = 0;
                                }

                                OutputSize -= 680;
                                OutputBuffer += 680;
                                ResultCount++;
                            }
                        }
                    }

                    ImportOffset -= 8;
                    pImportDesc++;
                    pImportThunk++;
                } while ((unsigned __int64)ImportOffset >= 8);
            }

            if (ReadFileResult == 1)
                ExFree(pModuleFileBuffer);
        }

        RemainingBytes -= 20;
        pModuleEntry += 5;
    } while ((unsigned __int64)RemainingBytes >= 0x14);

    return ResultCount;
}
char LookupDriverObjectEntry(
    unsigned int *pDriverArray,
    unsigned __int64 TargetAddress,
    __int64 pDriverEntry,
    __int64 EntrySize)
{
    ULONG EntryCount;
    __int64 SizeValue;
    char Result;
    ULONG Index;
    unsigned int *pCurrent;
    unsigned __int64 ImageBase;
    unsigned int ImageSize;

    EntryCount = *pDriverArray;
    SizeValue = EntrySize;
    Result = 1;
    if (!EntrySize)
        SizeValue = pDriverEntry;

    if (!GtRead(GtTotalSize | GtEprocessField104 | 0x100) ||
        *(unsigned __int64 *)GtRead(GtTotalSize | GtEprocessField104 | 0x100) > TargetAddress)
        return 0;

    Index = 0;
    pCurrent = pDriverArray + 2;
    if (EntryCount)
    {
        while (TargetAddress != *((_QWORD *)pCurrent + 1))
        {
            ++Index;
            pCurrent += 138;
            if (Index >= EntryCount)
                return Result;
        }
        if (pDriverEntry)
        {
            if (!*((_QWORD *)pCurrent + 2))
                *((_QWORD *)pCurrent + 2) = SizeValue;
            if (!*((_QWORD *)pCurrent + 3))
            {
                ImageBase = *(_QWORD *)(pDriverEntry + 24);
                if (ImageBase > (unsigned __int64)MmSystemRangeStart)
                    *((_QWORD *)pCurrent + 3) = ImageBase;
            }
            if (!pCurrent[8])
            {
                ImageSize = *(_DWORD *)(pDriverEntry + 32);
                if (ImageSize < 0xF00000)
                    pCurrent[8] = ImageSize;
            }
        }
        return 0;
    }
    return Result;
}
char ValidateDriverObjectAddress(
    __int64 pLdrEntry,
    __int64 pAddressOverride,
    char CheckAllAsciiFlag,
    unsigned int *pDriverTableEntry,
    int UnusedParam,
    __int64 pOutputBuffer)
{
    __int64 pAddressUsed;
    char Result;
    unsigned __int8 (__fastcall *pValidateFunc)(char *);
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    unsigned __int64 pEntryObject;
    unsigned int NameLength;
    unsigned __int64 ImageBase;
    unsigned int ImageSize;
    char *pNameBuffer;
    int TempImageSize;
    unsigned int CharIndex;
    char *pNameScan;
    size_t NameLen64;
    char *pNameBuf64;
    unsigned int BaseNameLength;
    char *pBaseNameBuffer;
    unsigned int CharIndex2;

    pAddressUsed = pAddressOverride;
    Result = 0;
    if (!pAddressOverride)
        pAddressUsed = pLdrEntry;

    pValidateFunc = (unsigned __int8 (__fastcall *)(char *))GtRead(GtObjectTypeCheckFlag);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);

    if (pValidateFunc && NtoskrnlImageBase && ModuleInfo && pLdrEntry)
    {
        if (pValidateFunc((char *)pLdrEntry) == 1)
        {
            pEntryObject = *(_QWORD *)(pLdrEntry + 40);
            if (pEntryObject)
            {
                if (pValidateFunc(*(char **)(pLdrEntry + 40)) == 1 &&
                    LookupDriverObjectEntry(pDriverTableEntry, pEntryObject, pLdrEntry, pAddressUsed) == 1)
                {
                    NameLength = *(unsigned __int16 *)(pEntryObject + 72);
                    ImageBase = *(_QWORD *)(pEntryObject + 48);
                    ImageSize = *(_DWORD *)(pEntryObject + 64);
                    pNameBuffer = *(char **)(pEntryObject + 80);

                    *(_QWORD *)(pOutputBuffer + 24) = ImageBase;
                    *(_DWORD *)(pOutputBuffer + 32) = ImageSize;
                    if (NameLength > 0x1FE)
                        NameLength = 510;
                    *(_BYTE *)pOutputBuffer = 1;
                    *(_QWORD *)(pOutputBuffer + 8) = pEntryObject;
                    *(_QWORD *)(pOutputBuffer + 16) = pAddressUsed;

                    if (ImageBase < (unsigned __int64)MmSystemRangeStart)
                        ImageBase = 0;
                    *(_QWORD *)(pOutputBuffer + 24) = ImageBase;
                    *(_DWORD *)(pOutputBuffer + 32) = ImageSize < 0xF00000 ? ImageSize : 0;

                    if (!ImageBase)
                    {
                        if (*(_QWORD *)(pLdrEntry + 24) > (unsigned __int64)MmSystemRangeStart)
                            ImageBase = *(_QWORD *)(pLdrEntry + 24);
                        *(_QWORD *)(pOutputBuffer + 24) = ImageBase;
                    }
                    if (!*(_DWORD *)(pOutputBuffer + 32))
                    {
                        TempImageSize = *(_DWORD *)(pOutputBuffer + 32);
                        if (*(_DWORD *)(pLdrEntry + 32) < 0xF00000u)
                            TempImageSize = *(_DWORD *)(pLdrEntry + 32);
                        *(_DWORD *)(pOutputBuffer + 32) = TempImageSize;
                    }
                    *(_BYTE *)(pOutputBuffer + 1) = 0;

                    if (pNameBuffer &&
                        pValidateFunc(pNameBuffer) == 1 &&
                        pValidateFunc(&pNameBuffer[NameLength - 1]) == 1)
                    {
                        if (CheckAllAsciiFlag == 1 || !NameLength)
                        {
                            NameLen64 = NameLength;
                            pNameBuf64 = pNameBuffer;
                            goto CopyName;
                        }
                        pNameScan = pNameBuffer;
                        for (CharIndex = 0; CharIndex < NameLength; CharIndex++)
                        {
                            if (*pNameScan < 0)
                                goto UseBaseName;
                            pNameScan++;
                        }
                        NameLen64 = NameLength;
                        pNameBuf64 = pNameBuffer;
                        goto CopyName;
                    }

UseBaseName:
                    BaseNameLength = *(unsigned __int16 *)(pEntryObject + 88);
                    pBaseNameBuffer = *(char **)(pEntryObject + 96);
                    if (BaseNameLength > 0x1FE)
                        BaseNameLength = 510;
                    if (pBaseNameBuffer &&
                        pValidateFunc(pBaseNameBuffer) == 1 &&
                        pValidateFunc(&pBaseNameBuffer[BaseNameLength - 1]) == 1)
                    {
                        if (CheckAllAsciiFlag != 1)
                        {
                            for (CharIndex2 = 0; CharIndex2 < BaseNameLength; CharIndex2++)
                            {
                                if (*pBaseNameBuffer < 0)
                                    goto SetNameEmpty;
                                pBaseNameBuffer++;
                            }
                            pBaseNameBuffer -= BaseNameLength;
                        }
                        NameLen64 = BaseNameLength;
                        pNameBuf64 = pBaseNameBuffer;
                        goto CopyName;
                    }

SetNameEmpty:
                    *(_WORD *)(pOutputBuffer + 36) = 0;
                    return 1;

CopyName:
                    memmove((void *)(pOutputBuffer + 36), pNameBuf64, NameLen64);
                    *(_WORD *)(pOutputBuffer + 546) = 0;
                    return 1;
                }
            }
        }
    }
    return Result;
}
void __fastcall FindHalDllInDriverList(
    unsigned int *pDriverArray,
    __int64 ArraySize,
    _QWORD *pImageBase,
    _DWORD *pImageSize)
{
    unsigned int *pEntry;
    unsigned int EntryIndex;
    _WORD *pLastSlash;
    _DWORD EncodedName[4];

    *pImageBase = 0;
    *pImageSize = 0;
    EncodedName[0] = 6357096;
    EncodedName[1] = 3014764;
    EncodedName[2] = 7077988;
    EncodedName[3] = 108;

    pEntry = pDriverArray + 2;
    EntryIndex = 0;
    if (*pDriverArray)
    {
        while (1)
        {
            pLastSlash = WStringFindLastChar((_WORD *)pEntry + 18, L'\\');
            if (pLastSlash)
            {
                if (pLastSlash[1] && !(unsigned int)WStringCompareCaseInsensitive((__int64)(pLastSlash + 1), (__int64)EncodedName))
                    break;
            }
            ++EntryIndex;
            pEntry += 138;
            if (EntryIndex >= *pDriverArray)
                return;
        }
        *pImageBase = *((_QWORD *)pEntry + 3);
        *pImageSize = pEntry[8];
    }
}
__int16 __fastcall BuildDriverImagePath(__int64 pNameString, unsigned int BufferSize, __int64 pOutputPath)
{
    __int64 Result;
    __int64 (*pValidateFunc)(void);
    unsigned int MaxLength;
    size_t SizeBytes;

    Result = GtRead(GtObjectTypeCheckFlag);
    pValidateFunc = (__int64 (*)(void))Result;
    if (Result)
    {
        MaxLength = *(_WORD *)pNameString & 0xFFFE;
        if (MaxLength > 0x1FE)
            MaxLength = 510;
        if (*(_QWORD *)(pNameString + 8))
        {
            if ((_BYTE)pValidateFunc() == 1)
            {
                SizeBytes = MaxLength;
                if ((_BYTE)((__int64 (__fastcall *)(__int64))pValidateFunc)(MaxLength + *(_QWORD *)(pNameString + 8) - 1) == 1)
                {
                    if (BufferSize >= 3
                        && MaxLength >= 0xA
                        && (*(_WORD *)(*(_QWORD *)(pNameString + 8) + 2LL * ((MaxLength >> 1) - 4)) == L'.')
                        && ((*(_WORD *)(*(_QWORD *)(pNameString + 8) + 2LL * ((MaxLength >> 1) - 3)) - L'D') & 0xFFDF) == 0
                        && ((*(_WORD *)(*(_QWORD *)(pNameString + 8) + 2LL * ((MaxLength >> 1) - 2)) - L'L') & 0xFFDF) == 0
                        && ((*(_WORD *)(*(_QWORD *)(pNameString + 8) + 2LL * ((MaxLength >> 1) - 1)) - L'L') & 0xFFDF) == 0)
                    {
                        if (SizeBytes + 44 < 0x200)
                        {
                            *(_DWORD *)pOutputPath = 5439580;
                            *(_DWORD *)(pOutputPath + 4) = 7536761;
                            *(_DWORD *)(pOutputPath + 8) = 6619252;
                            *(_DWORD *)(pOutputPath + 12) = 7471213;
                            *(_DWORD *)(pOutputPath + 16) = 7274607;
                            *(_DWORD *)(pOutputPath + 20) = 6029428;
                            *(_DWORD *)(pOutputPath + 24) = 7929971;
                            *(_DWORD *)(pOutputPath + 28) = 7602291;
                            *(_DWORD *)(pOutputPath + 32) = 7143525;
                            *(_DWORD *)(pOutputPath + 36) = 3276851;
                            *(_DWORD *)(pOutputPath + 40) = L'\\';
                            memmove((void *)(pOutputPath + 42), *(const void **)(pNameString + 8), SizeBytes);
                            *(_WORD *)(pOutputPath + 510) = 0;
                        }
                    }
                }
            }
        }
    }
    return (__int16)Result;
}
char __fastcall EnumerateDriverObjectTable(__int64 pEntry, __int64 TargetObject)
{
    char Result;
    __int64 ObjectPtr;
    unsigned __int64 *pAddressLimit;
    _QWORD *pTypeObject;
    __int64 pDeviceType;
    unsigned __int8 (__fastcall *ValidateFunc)(__int64);
    __int64 pHeader;
    unsigned __int64 AddressValue;
    char TypeFlag;

    Result = 0;
    ObjectPtr = TargetObject;
    if (!TargetObject)
        ObjectPtr = pEntry;

    if (*(_WORD *)pEntry == 4 && *(_WORD *)(pEntry + 2) == 336)
    {
        pAddressLimit = (unsigned __int64 *)GtRead(GtTotalSize | GtEprocessField104 | 0x100);
        pTypeObject = (_QWORD *)GtRead(GtDriverObjectListHead);
        pDeviceType = GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
        ValidateFunc = (unsigned __int8 (__fastcall *)(__int64))GtRead(GtObjectTypeCheckFlag);

        if (pAddressLimit && pTypeObject && pDeviceType && ValidateFunc)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
            {
                TypeFlag = CheckObjectTypeFlag(pEntry - 48);
                if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer02) != (unsigned __int8)TypeFlag)
                    return Result;
            }
            else
            {
                if (*(_QWORD *)(pEntry - 32) != *pTypeObject)
                    return Result;
            }

            AddressValue = *(_QWORD *)(pEntry + 40);
            if (AddressValue > *pAddressLimit && AddressValue)
                return Result;

            {
                unsigned __int64 HandleValue = *(unsigned int *)(pEntry + 32);
                if (HandleValue && ((HandleValue & 0x1F) != 0 || HandleValue >= *pAddressLimit))
                    return Result;
            }

            {
                unsigned __int64 GrantedAccess = *(_QWORD *)(pEntry + 24);
                if (GrantedAccess && ((GrantedAccess & 0xFFF) != 0 || GrantedAccess <= *pAddressLimit))
                    return Result;
            }

            pHeader = *(_QWORD *)(pEntry + 8);
            if (pHeader)
            {
                if (ValidateFunc(*(_QWORD *)(pEntry + 8)) != 1
                    || ValidateFunc(pHeader + 335) != 1
                    || *(_QWORD *)(pHeader + 8) != ObjectPtr
                    || (unsigned __int16)(*(_WORD *)(pHeader + 2) - 336) > 0xEAFu)
                    return Result;
            }

            AddressValue = *(_QWORD *)(pEntry + 48);
            if (AddressValue > *pAddressLimit || !AddressValue)
            {
                if (*(_QWORD *)(pEntry + 64) > *pAddressLimit
                    && CheckMemoryValid(*(void **)(pEntry + 64)) != 1
                    && *(_QWORD *)(pEntry + 64))
                    return Result;

                AddressValue = *(_QWORD *)(pEntry + 80);
                if (AddressValue > *pAddressLimit || !AddressValue)
                {
                    AddressValue = *(_QWORD *)(pEntry + 72);
                    if (AddressValue > *pAddressLimit || !AddressValue)
                    {
                        AddressValue = *(_QWORD *)(pEntry + 88);
                        if (AddressValue > *pAddressLimit || !AddressValue)
                        {
                            if ((*(_QWORD *)(pEntry + 96) > *pAddressLimit
                                && CheckMemoryValid(*(void **)(pEntry + 96)) != 1
                                && *(_QWORD *)(pEntry + 96))
                                || *(_QWORD *)(pEntry + 104) <= *pAddressLimit
                                || !*(_QWORD *)(pEntry + 104))
                                return 1;
                        }
                    }
                }
            }
        }
    }
    return Result;
}
char __fastcall EnumerateKernelDrivers(
    PVOID *pObjectStack,
    int StackSize,
    unsigned int *pOutputBuffer,
    int OutputSize)
{
    unsigned int BufferSize;
    _QWORD *pDeviceType;
    _QWORD *pTypeObject;
    unsigned __int8 (__fastcall *ValidateFunc)(unsigned __int64);
    _QWORD *pCurrentObj;
    int StackIndex;
    unsigned int IterationCount;
    unsigned int CurrentOffset;
    __int64 TypeMatch;
    unsigned int BucketIndex;
    _QWORD *pBucketEntry;
    unsigned int SubIndex;
    __int64 StackIndexCopy;
    _QWORD *pObject;
    _QWORD *pHeader;
    __int64 pNextObject;
    unsigned int ChainIndex;
    int StackIndexMax;
    unsigned int IterationCount2;
    _QWORD *pCurrentObjCopy;

    BufferSize = OutputSize;
    pDeviceType = (_QWORD *)GtRead(GtDriverObjectListHead);
    pTypeObject = (_QWORD *)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
    ValidateFunc = (unsigned __int8 (__fastcall *)(unsigned __int64))GtRead(GtObjectTypeCheckFlag);

    if (!pTypeObject || !pDeviceType || !ValidateFunc || StackSize <= 1)
        return (char)ValidateFunc;

    pCurrentObj = (_QWORD *)*pObjectStack;
    StackIndex = -1;
    IterationCount = 0;
    StackIndexMax = -1;
    pCurrentObjCopy = pCurrentObj;
    IterationCount2 = 0;

    if (*pObjectStack <= (PVOID)MmSystemRangeStart)
        return 0;

    StackIndexCopy = -1;
    while (1)
    {
        if (CheckMemoryValid(pCurrentObj) != 1 || IterationCount >= 0x100000)
            return 0;

        CurrentOffset = 552 * *pOutputBuffer + 560;

        if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
            TypeMatch = (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(pCurrentObj - 6));
        else
            TypeMatch = *(pCurrentObj - 4);

        BucketIndex = 0;
        do
        {
            if (CurrentOffset >= BufferSize)
                break;

            pBucketEntry = (_QWORD *)*pCurrentObj;
            SubIndex = 0;
            if ((ULONG_PTR)*pCurrentObj <= (ULONG_PTR)MmSystemRangeStart)
                goto NextBucket;

            StackIndexCopy = StackIndex;
            while (CurrentOffset < BufferSize && SubIndex < 0x10000)
            {
                pObject = (_QWORD *)pBucketEntry[1];
                pHeader = pObject - 6;

                if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
                {
                    if (TypeMatch == (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(pObject - 6)))
                        goto PushStack;
                }
                else
                {
                    if (TypeMatch == pHeader[2])
                        goto PushStack;
                }

                {
                    char IsDriverType;
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
                    {
                        char FlagValue = CheckObjectTypeFlagWrapper((__int64)(pObject - 6));
                        IsDriverType = (unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer01) == (unsigned __int8)FlagValue;
                    }
                    else
                    {
                        IsDriverType = *pTypeObject == pHeader[2];
                    }

                    pNextObject = 0;
                    if (IsDriverType)
                    {
                        pNextObject = (__int64)pObject;
                        goto ProcessChain;
                    }

                    char IsMatchDriver;
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
                    {
                        char FlagValue2 = CheckObjectTypeFlagWrapper((__int64)(pObject - 6));
                        IsMatchDriver = (unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer02) == (unsigned __int8)FlagValue2;
                    }
                    else
                    {
                        IsMatchDriver = *pDeviceType == pHeader[2];
                    }

                    if (IsMatchDriver)
                    {
                        if (ValidateDriverObjectAddress(
                                (__int64)pObject, (__int64)pObject, 1,
                                pOutputBuffer, OutputSize,
                                (__int64)(pOutputBuffer + 138 * *pOutputBuffer + 2)) == 1)
                        {
                            CurrentOffset += 552;
                            ++*pOutputBuffer;
                        }
                        pNextObject = pObject[1];
                    }

ProcessChain:
                    for (ChainIndex = 0; ; ChainIndex++)
                    {
                        if ((unsigned __int64)pNextObject <= (unsigned __int64)MmSystemRangeStart)
                            break;
                        if (ValidateFunc(pNextObject) != 1 || CurrentOffset >= BufferSize || ChainIndex >= 0x100)
                            goto NextBucketEntry;
                        if (ValidateDriverObjectAddress(
                                *(_QWORD *)(pNextObject + 8), *(_QWORD *)(pNextObject + 8), 1,
                                pOutputBuffer, BufferSize,
                                (__int64)(pOutputBuffer + 138 * *pOutputBuffer + 2)) == 1)
                        {
                            CurrentOffset += 552;
                            ++*pOutputBuffer;
                        }
                        pNextObject = *(_QWORD *)(pNextObject + 24);
                    }
                    goto SkipPush;
                }

PushStack:
                if (StackIndex >= StackSize - 1)
                    goto NextBucketEntry;
                pObjectStack[++StackIndexCopy] = pObject;
                StackIndexMax = StackIndex + 1;

SkipPush:
                pBucketEntry = (_QWORD *)*pCurrentObj;
                StackIndex = StackIndexMax;
                CurrentOffset = 552 * *pOutputBuffer + 560;
                SubIndex++;
                if ((unsigned __int64)pBucketEntry <= (unsigned __int64)MmSystemRangeStart)
                    break;
            }

NextBucketEntry:
            BucketIndex++;
            pCurrentObj++;
            CurrentOffset = 552 * *pOutputBuffer + 560;
        }
        while (BucketIndex < 0x25);

        if (StackIndexCopy >= 0)
        {
            pCurrentObj = (_QWORD *)pObjectStack[StackIndexCopy];
            StackIndex--;
            pCurrentObjCopy = pCurrentObj;
            StackIndexMax = StackIndex;
            StackIndexCopy--;
            if (CurrentOffset < BufferSize)
            {
                IterationCount = ++IterationCount2;
                if ((unsigned __int64)pCurrentObj > (unsigned __int64)MmSystemRangeStart)
                    continue;
            }
        }
        return 0;
    }

NextBucket:
    ;
    return 0;
}
char __fastcall OpenDriverFile(PCWSTR pFilePath)
{
    char Result;
    UNICODE_STRING UnicodePath;
    IO_STATUS_BLOCK StatusBlock;
    OBJECT_ATTRIBUTES Attr;
    HANDLE Handle;

    Result = 0;
    RtlInitUnicodeString(&UnicodePath, pFilePath);

    memset(&Attr, 0, sizeof(Attr));
    Attr.Length = sizeof(OBJECT_ATTRIBUTES);
    Attr.RootDirectory = NULL;
    Attr.Attributes = OBJ_CASE_INSENSITIVE;
    Attr.ObjectName = &UnicodePath;

    if (IoCreateFile(&Handle, FILE_READ_ATTRIBUTES, &Attr, &StatusBlock,
                     NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                     FILE_OPEN, 0, NULL, 0, CreateFileTypeNone, NULL, IO_IGNORE_SHARE_ACCESS_CHECK) >= 0)
    {
        Result = 1;
        ZwClose(Handle);
    }
    return Result;
}
__int64 __fastcall FindPESectionByRva(__int64 PeBase, unsigned int PeSize, unsigned int TargetRva)
{
    __int64 PeHeaderRva;
    __int64 Result;
    __int64 SectionHeaderStart;
    unsigned int SectionIndex;
    _DWORD *i;

    PeHeaderRva = *(int *)(PeBase + 60);
    Result = 0;
    SectionHeaderStart = *(unsigned __int16 *)(PeHeaderRva + PeBase + 20) + PeHeaderRva + PeBase + 24;

    if (TargetRva < PeSize)
    {
        SectionIndex = 0;
        if (*(_WORD *)(PeHeaderRva + PeBase + 6))
        {
            for (i = (_DWORD *)(SectionHeaderStart + 12);
                 TargetRva < *i || TargetRva >= *(i - 1) + *i;
                 i += 10)
            {
                if (++SectionIndex >= *(unsigned __int16 *)(PeHeaderRva + PeBase + 6))
                    return Result;
            }
            return SectionHeaderStart + 40LL * SectionIndex;
        }
    }
    return Result;
}
char __fastcall ValidateZeroPage(__int64 Address, unsigned __int64 LimitAddress)
{
    _BYTE *CurrentByte;
    unsigned int ByteIndex;

    CurrentByte = (_BYTE *)(Address & 0xFFFFFFFFFFFFF000ULL);
    ByteIndex = 0;
    while ((unsigned __int64)CurrentByte < LimitAddress)
    {
        if (*CurrentByte)
            return 0;
        ByteIndex++;
        CurrentByte++;
        if (ByteIndex >= 0x1000)
            return 1;
    }
    return 1;
}
unsigned int __fastcall CalcSectionAlignedSize(unsigned __int64 Address, unsigned __int64 LimitAddress)
{
    unsigned __int64 PageBase;
    unsigned int AlignedSize;

    PageBase = Address & 0xFFFFFFFFFFFFF000ULL;
    if (PageBase + 0x1000 <= LimitAddress)
        AlignedSize = (unsigned int)(LimitAddress - Address);
    else
        AlignedSize = (unsigned int)((PageBase + 0x1000) - Address);

    if (AlignedSize > 0x1000)
        AlignedSize = 0x1000;
    if (!AlignedSize)
        AlignedSize = 1;

    return AlignedSize;
}
unsigned int __fastcall CalcSectionRangeSize(unsigned __int64 StartAddress, unsigned __int64 EndAddress)
{
    if (EndAddress <= StartAddress)
        return 0;
    if (EndAddress - StartAddress > 0x1000)
        return 0x1000;
    return (unsigned int)(EndAddress - StartAddress);
}
unsigned int __fastcall CompareExportNamePrefix(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned __int64 LimitAddress)
{
    unsigned int PrefixLen;

    PrefixLen = 0;
    while ((unsigned __int64)(pBuffer1 + PrefixLen) < LimitAddress &&
           (unsigned __int64)(pBuffer2 + PrefixLen) < LimitAddress)
    {
        if (pBuffer1[PrefixLen] != pBuffer2[PrefixLen])
            return PrefixLen + 1;
        PrefixLen++;
        if (PrefixLen >= 0x32)
            break;
    }
    return PrefixLen;
}
char __fastcall CheckExportNamePrefixCombined(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize)
{
    unsigned int Index;
    _BYTE *p1, *p2;

    for (Index = 0; Index < CompareSize && Index < 8; Index++)
    {
        p1 = pBuffer1 + Index;
        p2 = pBuffer2 + Index;

        if (p1[0] != p2[0])
            return 0;

        if (Index == 1)
        {
            if ((p1[0] == 'N' && p1[1] == 't') ||
                (p1[0] == 'Z' && p1[1] == 'w') ||
                (p1[0] == 'R' && p1[1] == 't') ||
                (p1[0] == 'I' && p1[1] == 'o') ||
                (p1[0] == 'O' && p1[1] == 'b') ||
                (p1[0] == 'P' && p1[1] == 's') ||
                (p1[0] == 'S' && p1[1] == 'e') ||
                (p1[0] == 'M' && p1[1] == 'm') ||
                (p1[0] == 'C' && p1[1] == 'c') ||
                (p1[0] == 'E' && p1[1] == 'x') ||
                (p1[0] == 'K' && p1[1] == 'e') ||
                (p1[0] == 'C' && p1[1] == 'm') ||
                (p1[0] == 'P' && p1[1] == 'o') ||
                (p1[0] == 'P' && p1[1] == 'f') ||
                (p1[0] == 'H' && p1[1] == 'a') ||
                (p1[0] == 'K' && p1[1] == 'd') ||
                (p1[0] == 'E' && p1[1] == 't') ||
                (p1[0] == 'L' && p1[1] == 'd'))
                return 1;
        }
    }
    return 0;
}
char __fastcall CheckExportNamePrefixWin10V2(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize)
{
    unsigned int Index = 0;

    while (Index < CompareSize && Index < 12)
    {
        if (pBuffer1[Index] != pBuffer2[Index])
            return 0;

        if (Index == 1)
        {
            if ((pBuffer1[0] == 'N' && pBuffer1[1] == 't') ||
                (pBuffer1[0] == 'Z' && pBuffer1[1] == 'w') ||
                (pBuffer1[0] == 'R' && pBuffer1[1] == 't') ||
                (pBuffer1[0] == 'I' && pBuffer1[1] == 'o') ||
                (pBuffer1[0] == 'O' && pBuffer1[1] == 'b') ||
                (pBuffer1[0] == 'P' && pBuffer1[1] == 's') ||
                (pBuffer1[0] == 'S' && pBuffer1[1] == 'e') ||
                (pBuffer1[0] == 'M' && pBuffer1[1] == 'm') ||
                (pBuffer1[0] == 'C' && pBuffer1[1] == 'c') ||
                (pBuffer1[0] == 'E' && pBuffer1[1] == 'x') ||
                (pBuffer1[0] == 'K' && pBuffer1[1] == 'e') ||
                (pBuffer1[0] == 'F' && pBuffer1[1] == 'l') ||
                (pBuffer1[0] == 'C' && pBuffer1[1] == 'm') ||
                (pBuffer1[0] == 'P' && pBuffer1[1] == 'o') ||
                (pBuffer1[0] == 'P' && pBuffer1[1] == 'f') ||
                (pBuffer1[0] == 'H' && pBuffer1[1] == 'a') ||
                (pBuffer1[0] == 'K' && pBuffer1[1] == 'd') ||
                (pBuffer1[0] == 'E' && pBuffer1[1] == 't') ||
                (pBuffer1[0] == 'L' && pBuffer1[1] == 'd') ||
                (pBuffer1[0] == 'V' && pBuffer1[1] == 'f') ||
                (pBuffer1[0] == 'W' && pBuffer1[1] == 'd') ||
                (pBuffer1[0] == 'W' && pBuffer1[1] == 'p') ||
                (pBuffer1[0] == 'W' && pBuffer1[1] == 's') ||
                (pBuffer1[0] == 'T' && pBuffer1[1] == 'c') ||
                (pBuffer1[0] == 'U' && pBuffer1[1] == 'd') ||
                (pBuffer1[0] == 'I' && pBuffer1[1] == 'p') ||
                (pBuffer1[0] == 'N' && pBuffer1[1] == 'd') ||
                (pBuffer1[0] == 'F' && pBuffer1[1] == 's') ||
                (pBuffer1[0] == 'F' && pBuffer1[1] == 'v') ||
                (pBuffer1[0] == 'F' && pBuffer1[1] == 'w'))
                return 1;
        }
        Index++;
    }
    return 0;
}
char __fastcall FindExportEntryByAddress(__int64 TargetAddress, __int64 FilterTable, unsigned int FilterTableSize)
{
    unsigned int EntryIndex;
    unsigned int EntryCount;

    if (!FilterTable || !FilterTableSize)
        return 0;

    EntryCount = *(unsigned int *)FilterTable;
    for (EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++)
    {
        if (*(_QWORD *)(FilterTable + 8 + 88 * EntryIndex) == TargetAddress)
            return 1;
    }
    return 0;
}
char __fastcall BtreeSearchByKey(unsigned __int8 *pKeyData, unsigned int *pOutOrdinal, unsigned int EntryCount)
{
    unsigned int LowIndex, HighIndex, MidIndex;
    unsigned int MidValue;

    if (!EntryCount || !pKeyData || !pOutOrdinal)
        return 0;

    LowIndex = 0;
    HighIndex = EntryCount - 1;

    while (LowIndex <= HighIndex)
    {
        MidIndex = (LowIndex + HighIndex) / 2;
        MidValue = *(unsigned int *)(pKeyData + 4 * MidIndex);

        if (MidValue == *pOutOrdinal)
        {
            *pOutOrdinal = MidIndex;
            return 1;
        }

        if (MidValue < *pOutOrdinal)
            LowIndex = MidIndex + 1;
        else
            HighIndex = MidIndex - 1;
    }

    return 0;
}
char __fastcall ClassifyModuleTypeHalOrNt(const char *ModuleName, __int64 *pExportDirBase, unsigned int *pExportDirCount)
{
    if (!ModuleName || !pExportDirBase || !pExportDirCount)
        return 0;

    *pExportDirBase = 0;
    *pExportDirCount = 0;

    if (strstr(ModuleName, "hal") == ModuleName ||
        strstr(ModuleName, "HAL") == ModuleName ||
        strstr(ModuleName, "hal.dll") != NULL ||
        strstr(ModuleName, "HAL.dll") != NULL)
    {
        return 2;
    }

    if (strstr(ModuleName, "ntoskrnl") != NULL ||
        strstr(ModuleName, "ntkrnl") != NULL ||
        strstr(ModuleName, "ntkern") != NULL)
    {
        return 1;
    }

    return 0;
}
void __fastcall ParseExportSectionAndIndex(__int64 ImageBase, unsigned int ImageSize, unsigned int RegRefCount)
{
    if (!ImageBase || !ImageSize)
        return;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563)
    {
        if (RegRefCount <= 2)
        {
            // Win10+ 版本导出节解析
        }
    }
}
char __fastcall ReadModuleFileToBuffer(
    const char *ModuleName,
    void **ppBuffer,
    unsigned int *pFileSize,
    __int64 *pExportDirBase)
{
    void *pRawData;
    ULONG RawSize;

    if (!ModuleName || !ppBuffer || !pFileSize || !pExportDirBase)
        return 0;

    *ppBuffer = NULL;
    *pFileSize = 0;
    *pExportDirBase = 0;

    if (!ReadFileRawData((WORD *)ModuleName, &pRawData, &RawSize, 1))
        return 0;

    {
        void *pFileBuffer;
        ULONG FileSize;

        if (ReadNtFileToBuffer((PUCHAR)pRawData, RawSize, (PUCHAR *)&pFileBuffer, &FileSize) != 1)
        {
            ExFree(pRawData);
            return 0;
        }

        *ppBuffer = pFileBuffer;
        *pFileSize = FileSize;
        *pExportDirBase = (__int64)pRawData;

        ExFree(pRawData);
        return 1;
    }
}
char __fastcall ValidateEnumerationResult(__int64 pCheckFlagFunc, __int64 CurrentAddr, __int64 Offset)
{
    unsigned __int8 (__fastcall *pCheckFunc)(__int64);

    pCheckFunc = (unsigned __int8 (__fastcall *)(__int64))pCheckFlagFunc;
    if (!pCheckFunc)
        return 0;

    if (pCheckFunc(CurrentAddr) != 1)
        return 0;

    if (Offset && Offset < CurrentAddr)
        return 1;

    return 0;
}
__int64 ResolveDriverRelativeAddresses(__int64 DriverInfo, __int64 Flags, int **pRelocTable)
{
    char Result;
    __int64 KernelBase;
    unsigned int EntryCount;
    int *RelocBase;
    int *pRelocEntry;
    _QWORD *pCurrentEntry;
    __int64 LoopCount;
    int RelocShift;

    Result = 0;
    KernelBase = GtRead(GtKernelModuleBase);
    if (KernelBase)
    {
        EntryCount = *(_DWORD *)(DriverInfo + 4);
        RelocBase = *pRelocTable;
        if (EntryCount)
        {
            pRelocEntry = *pRelocTable;
            pCurrentEntry = (_QWORD *)(DriverInfo + 16);
            LoopCount = EntryCount;
            do
            {
                *pCurrentEntry = KernelBase + *((unsigned int *)pCurrentEntry - 1);
                pCurrentEntry += 6;
                RelocShift = *pRelocEntry++ >> 4;
                *(pCurrentEntry - 5) = (_QWORD)((char *)RelocBase + RelocShift);
                --LoopCount;
            }
            while (LoopCount);
        }
        return 1;
    }
    return Result;
}
__int64 ResolveDriverEntryAddresses(__int64 DriverInfo)
{
    char Result;
    unsigned int EntryCount;
    __int64 pEntry;
    __int64 LoopCount;
    unsigned int EntryIndex;
    __int64 pCurrentEntry;
    unsigned int CompareSize;
    unsigned int ByteIndex;
    __int64 ResolvedAddress;

    Result = 0;
    if (GtRead(GtKernelModuleBase))
    {
        EntryCount = *(_DWORD *)(DriverInfo + 4);
        if (EntryCount)
        {
            pEntry = DriverInfo + 16;
            LoopCount = EntryCount;
            do
            {
                if (*(_QWORD *)(pEntry + 8) != *(_QWORD *)pEntry)
                    *(_BYTE *)(pEntry + 16) = 1;
                pEntry += 48;
                --LoopCount;
            }
            while (LoopCount);
        }
        EntryIndex = 0;
        if (EntryCount)
        {
            pCurrentEntry = DriverInfo + 16;
            do
            {
                CompareSize = 16;
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800 && *(_WORD *)(pCurrentEntry + 18) == 9727)
                    CompareSize = 6;
                if (MmIsAddressValid((PVOID)(*(_QWORD *)pCurrentEntry + 15LL)) == 1)
                {
                    if ((unsigned int)MemoryCompare(*(_QWORD *)pCurrentEntry, (char *)(48LL * EntryIndex + DriverInfo + 34), CompareSize))
                    {
                        *(_BYTE *)(pCurrentEntry + 17) = 1;
                        if (!*(_BYTE *)(pCurrentEntry + 16))
                        {
                            for (ByteIndex = 0; ByteIndex < CompareSize; ++ByteIndex)
                            {
                                if (!MmIsAddressValid((PVOID)(*(_QWORD *)pCurrentEntry + ByteIndex)))
                                    break;
                            }
                            if (ByteIndex && ReturnFalseStub() == 1)
                                *(_QWORD *)(pCurrentEntry + 8) = ResolvedAddress;
                        }
                    }
                }
                ++EntryIndex;
                pCurrentEntry += 48;
            }
            while (EntryIndex < EntryCount);
        }
        return 1;
    }
    return Result;
}
__int64 ResolveKernelModuleBasePair(__int64 CpuNumber, ULONG_PTR *pMsrPair)
{
    unsigned __int64 MsrBaseLstar;
    unsigned __int64 Msr;

    MsrBaseLstar = ReadMsr(0xC0000083);
    if (MsrBaseLstar && *pMsrPair && MsrBaseLstar != *pMsrPair)
        pMsrPair[2] = MsrBaseLstar;
    Msr = ReadMsr(0xC0000082);
    if (Msr)
    {
        if (pMsrPair[1])
        {
            if (Msr != pMsrPair[1])
                pMsrPair[3] = Msr;
        }
    }
    return 1;
}
__int64 ResolveKernelModuleBasePair2(__int64 CpuNumber, ULONG_PTR *pMsrPair)
{
    unsigned __int64 MsrBaseLstar;
    unsigned __int64 Msr;

    MsrBaseLstar = ReadMsr(0xC0000083);
    if (MsrBaseLstar && *pMsrPair && MsrBaseLstar != *pMsrPair)
        pMsrPair[2] = MsrBaseLstar;
    Msr = ReadMsr(0xC0000082);
    if (Msr)
    {
        if (pMsrPair[1])
        {
            if (Msr != pMsrPair[1])
                pMsrPair[3] = Msr;
        }
    }
    return 1;
}
__int64 AdjustKernelModuleSectionPointers(void)
{
    __int64 EprocessField191;
    __int64 result;
    __int64 EprocessField192;
    __int64 AdjustedOffset;

    EprocessField191 = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField187 | 0x100));
    result = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField188 | 0x100));
    EprocessField192 = result;
    if (EprocessField191 && result)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
        {
            result = GtRead(GtWindowsBuildNumber);
            if ((_DWORD)result != 9200)
                return result;
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessField189 | 0x100), EprocessField191 + 16);
            AdjustedOffset = EprocessField192 + 16;
        }
        else
        {
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessField189 | 0x100), EprocessField191 + 8);
            AdjustedOffset = EprocessField192 + 8;
        }
        return GtWrite((enum _GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | 0x100), AdjustedOffset);
    }
    return result;
}
__int64 __fastcall ResolveKernelModuleIndex(
    enum _GLOBAL_TABLE_INDEX SectionType,
    enum _GLOBAL_TABLE_INDEX ResultTableIndex,
    enum _GLOBAL_TABLE_INDEX TargetTableIndex)
{
    __int64 Result;
    struct _KPROCESS *TargetProcess;
    __int64 CopyBase;
    unsigned int CopySize;
    __int64 ModuleBase;
    unsigned int KernelPESectionByType;
    unsigned int MaxSectionCount;
    unsigned int SyscallIndex;
    __int64 RvaOffset;
    struct _KAPC_STATE ApcState;

    Result = GtRead(TargetTableIndex);
    if (!Result)
    {
        TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
        if (IoGetCurrentProcess() == TargetProcess)
            TargetProcess = 0;
        if (TargetProcess)
            KeStackAttachProcess(TargetProcess, &ApcState);
        CopyBase = GtRead(GtEprocessField22);
        CopySize = (unsigned int)GtRead(GtEprocessField23);
        ModuleBase = GtRead(GtNtoskrnlModuleBase);
        KernelPESectionByType = (unsigned int)FindKernelPESectionByType(SectionType);
        MaxSectionCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
        if (CopyBase && CopySize && ModuleBase && KernelPESectionByType && KernelPESectionByType < MaxSectionCount)
        {
            SyscallIndex = (unsigned int)ResolveSyscallToAddress(KernelPESectionByType);
            if (SyscallIndex && SyscallIndex < CopySize)
            {
                RvaOffset = SyscallIndex;
                GtWrite(ResultTableIndex, SyscallIndex);
                Result = ModuleBase + RvaOffset;
                GtWrite(TargetTableIndex, Result);
            }
        }
        if (TargetProcess)
            KeUnstackDetachProcess(&ApcState);
    }
    return Result;
}
__int64 __fastcall WalkKernelModuleList(unsigned __int64 *pModuleList, _DWORD *pOutputBuffer, _DWORD *pMaxEntries)
{
    unsigned int EntryCount;
    unsigned int IterCount;
    unsigned __int64 pListEntry;

    EntryCount = 0;
    IterCount = 0;
    for (pListEntry = *pModuleList;
         pListEntry > (unsigned __int64)MmSystemRangeStart
         && (unsigned __int64 *)pListEntry != pModuleList
         && IterCount < 0x1000
         && *pMaxEntries
         && CheckMemoryValid((void *)pListEntry) == 1
         && CheckMemoryValid((void *)(pListEntry + 31)) == 1;
         pListEntry = *(_QWORD *)pListEntry)
    {
        pOutputBuffer[4 * *pOutputBuffer + 4] = *(_DWORD *)(pListEntry + 24);
        *(_QWORD *)&pOutputBuffer[4 * (*pOutputBuffer)++ + 2] = *(_QWORD *)(pListEntry + 16);
        ++EntryCount;
        ++IterCount;
    }
    return EntryCount;
}
__int64 BuildDriverInfoEntries(unsigned int *EntryArray, unsigned int BufferSize)
{
    char Result;
    __int64 ContextTablePtr;
    __int64 DriverContextTable;
    unsigned int ExistingCount;
    unsigned int TotalCount;
    unsigned int LoopIndex;
    __int64 DriverBaseAddr;
    __int64 EntryOffset;
    unsigned int NewTotalCount;
    unsigned int FillIndex;
    __int64 EntryOffset2;
    int RawEntryData;

    Result = 0;
    ContextTablePtr = GtRead(GtFindHookTargetFirstMatchAddr2);
    if (ContextTablePtr)
    {
        DriverContextTable = *(_QWORD *)ContextTablePtr;
        ExistingCount = *EntryArray;
        TotalCount = *(_DWORD *)(ContextTablePtr + 16);
        LoopIndex = 0;
        if (TotalCount < *EntryArray)
            TotalCount = *EntryArray;
        EntryArray[1] = TotalCount;
        if (ExistingCount)
        {
            do
            {
                DriverBaseAddr = DriverContextTable + (*(int *)(DriverContextTable + 4LL * LoopIndex) >> 4);
                EntryOffset = 42LL * LoopIndex;
                *(_QWORD *)&EntryArray[EntryOffset + 40] = DriverBaseAddr;
                if (DriverBaseAddr != *(_QWORD *)&EntryArray[EntryOffset + 38])
                    *(unsigned char *)&EntryArray[EntryOffset + 42] = 1;
                ++LoopIndex;
            }
            while (LoopIndex < *EntryArray);
        }
        NewTotalCount = EntryArray[1];
        FillIndex = *EntryArray;
        if (NewTotalCount > *EntryArray && BufferSize >= 168 * NewTotalCount + 176 && FillIndex < NewTotalCount)
        {
            do
            {
                EntryOffset2 = 42LL * FillIndex;
                EntryArray[EntryOffset2 + 2] = FillIndex;
                RawEntryData = *(_DWORD *)(DriverContextTable + 4LL * FillIndex);
                *(unsigned short *)&EntryArray[EntryOffset2 + 42] = 0;
                EntryArray[EntryOffset2 + 36] = 0;
                *(_QWORD *)&EntryArray[EntryOffset2 + 38] = 0;
                ++FillIndex;
                *(_QWORD *)&EntryArray[EntryOffset2 + 40] = DriverContextTable + (RawEntryData >> 4);
                *(unsigned short *)&EntryArray[EntryOffset2 + 3] = 0;
            }
            while (FillIndex < EntryArray[1]);
        }
        return 1;
    }
    return Result;
}
__int64 ParseKernelModuleDiskInfo(void)
{
    bool Result;
    unsigned int FileSize;
    void *FileBuffer;

    Result = 0;
    if (GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField136 | 0x100)) && ReadNtFileDiskInfo(&FileBuffer, &FileSize))
    {
        Result = FindHalInitPatternOffsets((__int64)FileBuffer, FileSize) == 1;
        ExFree(FileBuffer);
    }
    return Result;
}
void ParseRegistryDriverExportDir(void)
{
    char Result;
    __int64 *pExportTable;
    __int64 NtoskrnlBase;
    unsigned int *pIndexPtr;
    __int64 EntryCount;
    __int64 TargetRva;
    char *pFileBuffer;
    unsigned int FileSize;
    char *pRawData;

    Result = 0;
    pExportTable = GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtCallbackField50 | 0x3000));
    NtoskrnlBase = GtRead((enum _GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs5 | GtEprocessField54));
    if (NtoskrnlBase && ReadRegistryDriverFile(&pRawData, &FileSize))
    {
        if (ParseKernelModuleSectionTable((__int64)pRawData, FileSize, (__int64)pExportTable) == 1
            && ParseNtExportDir((PUCHAR)pRawData, FileSize, NtoskrnlBase, 0) == 1)
        {
            pIndexPtr = (unsigned int *)pExportTable + 1;
            EntryCount = 28;
            do
            {
                TargetRva = *pIndexPtr;
                *(pIndexPtr - 1) = 0;
                if ((_DWORD)TargetRva && (unsigned int)((int)TargetRva + 32) <= FileSize)
                {
                    *(pIndexPtr - 1) = 1;
                    pFileBuffer = pRawData;
                    *(_OWORD *)(pIndexPtr + 3) = *(_OWORD *)&pRawData[TargetRva];
                    *(_OWORD *)(pIndexPtr + 7) = *(_OWORD *)&pFileBuffer[TargetRva + 16];
                }
                pIndexPtr += 12;
                --EntryCount;
            }
            while (EntryCount);
            Result = 1;
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs6 | GtEprocessField54), 1);
        }
        ExFree(pRawData);
        if (Result == 1)
            FillExportEntrySlot((__int64)pExportTable);
    }
}
__int64 ParseExportDirForDriver(__int64 DriverInfo, __int64 Context, __int64 PeBuffer, unsigned int PeSize)
{
    char Result;
    __int64 KernelModuleBase;
    unsigned int EntryCount;
    unsigned int LoopIndex;
    unsigned int *pEntry;
    __int64 EntryValue;

    Result = 0;
    KernelModuleBase = GtRead(GtKernelModuleBase);
    if (KernelModuleBase && ParseNtExportDir((PUCHAR)PeBuffer, PeSize, KernelModuleBase, 0) == 1)
    {
        EntryCount = *(_DWORD *)(DriverInfo + 4);
        LoopIndex = 0;
        if (!EntryCount)
            return 1;
        pEntry = (unsigned int *)(DriverInfo + 12);
        do
        {
            EntryValue = *pEntry;
            if ((unsigned int)((int)EntryValue + 16) > PeSize)
                break;
            ++LoopIndex;
            pEntry += 12;
            *(_OWORD *)((char *)pEntry - 26) = *(_OWORD *)(EntryValue + PeBuffer);
        }
        while (LoopIndex < EntryCount);
        if (LoopIndex >= EntryCount)
            return 1;
    }
    return Result;
}
void BuildProcessContextExportTable(void)
{
    __int64 NtoskrnlBase;
    __int64 LoopCount;
    unsigned int *pContextEntry;
    int FuncRva;
    __int64 FuncRvaCopy;
    __int64 LoopCount2;
    unsigned int *pTargetEntry;
    int TargetRva;
    __int64 TargetRvaCopy;
    unsigned int FileSize;
    char *pFileBuffer;

    NtoskrnlBase = GtRead((enum _GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs8 | GtEprocessField54));
    if (NtoskrnlBase && ReadNtFileForProcessContext((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (ParseNtImageSections2((__int64)pFileBuffer, FileSize) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
        {
            LoopCount = 28;
            pContextEntry = (unsigned int *)GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtPspExitThreadAddr | 0x3400)) + 1;
            do
            {
                FuncRva = *pContextEntry;
                *(pContextEntry - 1) = 0;
                if (FuncRva && (unsigned int)(FuncRva + 16) <= FileSize)
                {
                    GtWrite((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField182), 1);
                    FuncRvaCopy = *pContextEntry;
                    *(pContextEntry - 1) = 1;
                    *(_OWORD *)(pContextEntry + 3) = *(_OWORD *)&pFileBuffer[FuncRvaCopy];
                }
                pContextEntry += 12;
                --LoopCount;
            }
            while (LoopCount);
            LoopCount2 = 27;
            pTargetEntry = (unsigned int *)GtAlloc((enum _GLOBAL_TABLE_INDEX)15650) + 1;
            do
            {
                TargetRva = *pTargetEntry;
                *(pTargetEntry - 1) = 0;
                if (TargetRva && (unsigned int)(TargetRva + 16) <= FileSize)
                {
                    GtWrite((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField183), 1);
                    TargetRvaCopy = *pTargetEntry;
                    *(pTargetEntry - 1) = 1;
                    *(_OWORD *)(pTargetEntry + 3) = *(_OWORD *)&pFileBuffer[TargetRvaCopy];
                }
                pTargetEntry += 12;
                --LoopCount2;
            }
            while (LoopCount2);
        }
        ExFree(pFileBuffer);
    }
}
char ReadRegistryDriverFile(char **pFileBuffer, unsigned int *pFileSize)
{
    char Result;
    size_t FileSize;
    void *pRawData;
    int EncodedBuffer[20];

    Result = 0;
    EncodedBuffer[0] = 5439580;
    EncodedBuffer[1] = 7536761;
    EncodedBuffer[2] = 6619252;
    EncodedBuffer[3] = 5374061;
    EncodedBuffer[4] = 7274607;
    EncodedBuffer[5] = 6029428;
    EncodedBuffer[6] = 7929971;
    EncodedBuffer[7] = 7602291;
    EncodedBuffer[8] = 7143525;
    EncodedBuffer[9] = 3276851;
    EncodedBuffer[10] = 6553692;
    EncodedBuffer[11] = 6881394;
    EncodedBuffer[12] = 6619254;
    EncodedBuffer[13] = 7536754;
    EncodedBuffer[14] = 7209052;
    EncodedBuffer[15] = 6684784;
    EncodedBuffer[16] = 3014771;
    EncodedBuffer[17] = 7929971;
    EncodedBuffer[18] = 115;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedBuffer, &pRawData, (ULONG *)&FileSize, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)pRawData, (unsigned int)FileSize, pFileBuffer, pFileSize) == 1;
        ExFree(pRawData);
    }
    return Result;
}
char ParseKernelModuleSectionTable(__int64 FileBuffer, unsigned int FileSize, __int64 OutputTable)
{
    __int64 PeOffset;
    char Result;
    __int64 NtoskrnlBase;
    __int64 SectionDirRva;
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
    PE_DECODE_CONTEXT SectionContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 AccumulatedOffset;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
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

    PeOffset = *(int *)(FileBuffer + 60);
    Result = 0;
    NtoskrnlBase = GtRead((GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs5 | GtEprocessField54));
    if (NtoskrnlBase)
    {
        SectionDirRva = *(unsigned int *)(PeOffset + FileBuffer + 40);
        if ((unsigned int)SectionDirRva < FileSize && (unsigned int)((int)SectionDirRva + 4096) < FileSize)
        {
            IsTargetSection = 0;
            InitPESectionReadContext(FileBuffer + SectionDirRva, (ULONG)4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
            SectionIndex = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            {
                *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                ComputedOffset = (int)(SectionFileOffset + AccumulatedOffset);
                AccumulatedOffset += SectionFileOffset;
                SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                if (SectionType == 1369)
                {
                    SectionRva = (unsigned int)(ComputedOffset + SectionDataSize - FileBuffer);
                    if (SectionRva && SectionRva < FileSize)
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
                        SectionRva = (unsigned int)(ComputedOffset + SectionDataSize - FileBuffer);
                        if (SectionRva && SectionRva < FileSize)
                        {
LABEL_FOUND_SECTION:
                            SectionDirRva = SectionRva;
                            break;
                        }
                    }
                    IsTargetSection = 0;
                }
                if ((unsigned int)++SectionIndex >= 0x14)
                    break;
            }
        }
        if ((unsigned int)SectionDirRva < FileSize && (unsigned int)((int)SectionDirRva + 4096) < FileSize)
        {
            InitPESectionReadContext(FileBuffer + (unsigned int)SectionDirRva, (ULONG)4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
            memset(SectionOffsetTable, 0, sizeof(SectionOffsetTable));
            for (EntryIndex = 0; EntryIndex < 0x3E8; ++EntryIndex)
            {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
                    break;
                ComputedOffset2 = (int)(SectionFileOffset + AccumulatedOffset);
                AccumulatedOffset += SectionFileOffset;
                SectionType2 = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                if (SectionType2 == 1349)
                    break;
                SectionFlags = (int)SectionCharacteristics;
                if (SectionType2 == 1298 && SectionAlignment == 0x40000)
                {
                    if (FieldMisc && SectionCharacteristics == 64)
                    {
                        SectionRva2 = (unsigned int)(ComputedOffset2 + FieldMisc - FileBuffer);
                        if (SectionRva2 && SectionRva2 < FileSize)
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
char ReadNtoskrnlForObjectContext(char **pFileBuffer, unsigned int *pFileSize)
{
    char Success;
    size_t RawDataSize;
    void *pRawData;
    int EncodedPath[24];

    Success = 0;
    EncodedPath[0] = 5439580;
    EncodedPath[1] = 7536761;
    EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061;
    EncodedPath[4] = 7274607;
    EncodedPath[5] = 6029428;
    EncodedPath[6] = 7929971;
    EncodedPath[7] = 7602291;
    EncodedPath[8] = 7143525;
    EncodedPath[9] = 3276851;
    EncodedPath[10] = 6553692;
    EncodedPath[11] = 6881394;
    EncodedPath[12] = 6619254;
    EncodedPath[13] = 7536754;
    EncodedPath[14] = 6881372;
    EncodedPath[15] = 3145784;
    EncodedPath[16] = 3276852;
    EncodedPath[17] = 7471216;
    EncodedPath[18] = 3014772;
    EncodedPath[19] = 7929971;
    EncodedPath[20] = 115;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &pRawData, (ULONG *)&RawDataSize, 1))
    {
        Success = ReadNtFileToBuffer((PUCHAR)pRawData, (unsigned int)RawDataSize, pFileBuffer, pFileSize) == 1;
        ExFree(pRawData);
    }
    return Success;
}
char FindPatchThreadWindowsExport(
    __int64 FileBuffer,
    unsigned int FileSize)
{
    char Result;
    ULONG ExportOffset;
    char FuncName[24];

    ExportOffset = 0;
    strcpy(FuncName, "PatchThreadWindows");
    FuncName[19] = 0;

    Result = (char)GtRead(GtFwpsDispatchTableCount);
    if (!Result)
    {
        Result = LookupExportByName(
            (PUCHAR)FileBuffer,
            FileSize,
            FuncName,
            &ExportOffset);

        if (Result == 1)
        {
            if (ExportOffset)
            {
                if (ExportOffset < FileSize)
                    Result = (char)GtWrite(GtNtOpenProcessHookAddress, ExportOffset);
            }
        }
    }

    return Result;
}
char QueryProcessModuleFilePath(
    __int64 Process,
    __int64 ModuleBase,
    _WORD *pOutputBuffer,
    int BufferSize)
{
    char Result;
    unsigned int (__fastcall *pValidateFunc)(__int64, __int64 *);
    void (__fastcall *pCloseFunc)(__int64);
    unsigned int (__fastcall *pOpenHandleFunc)(__int64, __int64, ULONG64, __int64, ULONG64, char, __int64 *);
    ULONG64 *pTypeValue;
    void (__fastcall *pFreeFunc)(__int64);
    __int64 (__fastcall *pEnumModuleFunc)(__int64, __int64, __int64, ULONG64 *, __int64, char *);
    unsigned int PrevModeOffset;
    ULONG64 *pBuffer;
    struct _KTHREAD *CurrentThread;
    __int64 PrevModeOffsetCopy;
    char SavedPrevMode;
    int Status;
    _WORD *pPathString;
    unsigned __int16 StringLength;
    _WORD *LastChar;
    _WORD *pFileName;
    __int64 CopyLength;
    char SavedPrevModeByte;
    __int64 Handle;
    __int64 ObjectType;
    char ApcState[88];

    Result = 0;

    pValidateFunc = (unsigned int (__fastcall *)(__int64, __int64 *))GtRead(GtValidateObjectTypeFunc);
    pCloseFunc = (void (__fastcall *)(__int64))GtRead(GtCloseHandleFunc);
    pOpenHandleFunc = (unsigned int (__fastcall *)(__int64, __int64, ULONG64, __int64, ULONG64, char, __int64 *))GtRead(GtEprocessField54);
    pTypeValue = (ULONG64 *)GtRead(GtTotalSize);
    pFreeFunc = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    pEnumModuleFunc = (__int64 (__fastcall *)(__int64, __int64, __int64, ULONG64 *, __int64, char *))GtRead(GtKernelDataField03);

    if (!pEnumModuleFunc)
    {
        ResolveModuleEnumBase();
        pEnumModuleFunc = (__int64 (__fastcall *)(__int64, __int64, __int64, ULONG64 *, __int64, char *))GtRead(GtKernelDataField03);
    }

    PrevModeOffset = (unsigned int)GtRead(GtPrevModeOffset);
    *pOutputBuffer = 0;

    if (pValidateFunc &&
        pCloseFunc &&
        pOpenHandleFunc &&
        pTypeValue &&
        pFreeFunc &&
        pEnumModuleFunc &&
        PrevModeOffset != -1 &&
        !pValidateFunc(Process, &ObjectType))
    {
        SavedPrevModeByte = 0;
        if (!pOpenHandleFunc(ObjectType, 512, 0, 0x10000000, *pTypeValue, SavedPrevModeByte, &Handle))
        {
            pBuffer = (ULONG64 *)ExAlloc(1, 0x1000);
            if (pBuffer)
            {
                CurrentThread = KeGetCurrentThread();
                PrevModeOffsetCopy = PrevModeOffset;
                SavedPrevMode = *((char *)CurrentThread + PrevModeOffset);
                *((char *)CurrentThread + PrevModeOffsetCopy) = 0;

                Status = (int)pEnumModuleFunc(Handle, ModuleBase, 2, pBuffer, 4096, ApcState);
                *((char *)CurrentThread + PrevModeOffsetCopy) = SavedPrevMode;

                if (!Status)
                {
                    pPathString = (_WORD *)pBuffer[1];
                    if (pPathString == (_WORD *)(pBuffer + 2))
                    {
                        StringLength = *(__int16 *)pBuffer;
                        if (StringLength > 2)
                        {
                            if (BufferSize)
                            {
                                if ((ULONG64)StringLength + 18 < 0x1000)
                                    pPathString[(ULONG64)StringLength >> 1] = 0;
                                else
                                    *((_WORD *)pBuffer + 2047) = 0;

                                LastChar = WStringFindLastChar((_WORD *)pBuffer[1], 92);
                                if (!LastChar || (pFileName = LastChar + 1, !LastChar[1]))
                                    pFileName = (_WORD *)pBuffer[1];

                                StringLength = (unsigned __int16)GetStringLength(pFileName);
                                CopyLength = StringLength;
                                if (StringLength > (unsigned int)(BufferSize - 1))
                                    CopyLength = (unsigned int)(BufferSize - 1);

                                memmove(pOutputBuffer, pFileName, (unsigned int)(2 * CopyLength));
                                pOutputBuffer[CopyLength] = 0;
                                Result = 1;
                            }
                        }
                    }
                }
                ExFree(pBuffer);
            }
            pFreeFunc(Handle);
        }
        pCloseFunc(ObjectType);
    }

    return Result;
}
char ScanKernelPeExportSection()
{
    char Result;
    unsigned int ExportDirOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int ComputedOffset;
    __int16 SectionType;
    unsigned int ExportRva;
    PE_DECODE_CONTEXT SectionContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 SectionFileOffset;
    ULONG SectionEntry[112];            // 描述符：原 [20] 仅 80 字节
    __int64 FieldValueSize;
    int FieldCount;
    int SectionDataSize;
    __int64 FieldFlags;
    unsigned int SectionAlignedSize;
    __int64 pSectionEntryBase;

    Result = 0;

    // 读取：导出目录偏移(0x4228)、ntoskrnl基址(32)、ntoskrnl大小(33)、模块基址(3)、映像大小(2)
    ExportDirOffset = (unsigned int)GtRead(GtUninstallHookSyscallPeOffset);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);

    if (ExportDirOffset &&
        ExportDirOffset < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + ExportDirOffset),
            (ULONG)(NtImageSize - ExportDirOffset),
            2,
            0,
            -1,
            0,
            0,
            (__int64)&SectionContext);

        for (SectionIndex = 0; SectionIndex < 0x64; ++SectionIndex)
        {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
                break;

            ComputedOffset = SectionAlignedSize + (ULONG)SectionFileOffset;
            SectionFileOffset += SectionAlignedSize;
            SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

            if (SectionType == 1349)
                break;

            if (SectionType == 1298 && FieldFlags == 0x40000)
            {
                if (SectionDataSize)
                {
                    if (FieldValueSize == 64 && FieldCount == 1)
                    {
                        ExportRva = (unsigned int)(ComputedOffset + SectionDataSize - NtImageBase);
                        if (ExportRva)
                        {
                            if (ExportRva < NtImageSize)
                            {
                                GtWrite(GtCallbackField04, NtoskrnlModuleBase + ExportRva);
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }

    return Result;
}
char ScanKernelPeExportData()
{
    char Result;
    unsigned int FirstPassOffset;
    unsigned int SecondPassOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int ComputedOffset;
    __int16 SectionType;
    unsigned int ExportRva;
    PE_DECODE_CONTEXT SectionContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 SectionFileOffset;
    ULONG SectionEntry[112];            // 描述符：原 [20] 仅 80 字节
    __int64 FieldValueSize;
    __int64 FieldFlags;
    int SectionDataSize;
    unsigned int SectionAlignedSize;
    __int64 pSectionEntryBase;

    Result = 0;

    // 读取 GT 值：0x435D(未命名偏移)、0x20(GtEprocessField22)、0x21(GtEprocessField23)、
    // 0x3(GtNtoskrnlModuleBase)、0x2(GtNtoskrnlImageSize)
    FirstPassOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x435D);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);

    if (!FirstPassOffset ||
        FirstPassOffset >= NtImageSize ||
        !NtImageBase ||
        !NtImageSize ||
        !NtoskrnlModuleBase ||
        !NtoskrnlImageSize)
    {
        return Result;
    }

    // 第一轮扫描：最多 5 个条目，查找 Type 0x559
    InitPESectionReadContext(
        (__int64)(NtImageBase + FirstPassOffset),
        (ULONG)(NtImageSize - FirstPassOffset),
        2,
        0,
        -1,
        0,
        0,
        (__int64)&SectionContext);

    SecondPassOffset = 0;
    SectionIndex = 0;
    while (SectionIndex < 5)
    {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            break;

        ComputedOffset = SectionAlignedSize + (ULONG)SectionFileOffset;
        SectionFileOffset += SectionAlignedSize;
        SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (SectionType == 0x559 && SectionDataSize)
        {
            unsigned int TempRva = (unsigned int)(SectionDataSize - NtImageBase + (ULONG)ComputedOffset);
            if (TempRva && TempRva < NtImageSize)
            {
                SecondPassOffset = TempRva;
                break;
            }
        }

        ++SectionIndex;
    }

    if (!SecondPassOffset || SecondPassOffset >= NtImageSize)
        return Result;

    // 第二轮扫描：最多 100 个条目，查找 Type 0x4DB
    InitPESectionReadContext(
        (__int64)(NtImageBase + SecondPassOffset),
        (ULONG)(NtImageSize - SecondPassOffset),
        2,
        0,
        -1,
        0,
        0,
        (__int64)&SectionContext);

    SectionIndex = 0;
    while (SectionIndex < 0x64)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            break;

        ComputedOffset = SectionAlignedSize + (ULONG)SectionFileOffset;
        SectionFileOffset += SectionAlignedSize;
        SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (SectionType == 0x4DB &&
            FieldFlags == 0x40000 &&
            FieldValueSize == 0x40)
        {
            ExportRva = (unsigned int)(SectionDataSize - NtImageBase + (ULONG)ComputedOffset);
            if (ExportRva && ExportRva < NtImageSize)
            {
                // 写入 GT 0x33D = GtCallbackField108
                GtWrite(GtCallbackField108, NtoskrnlModuleBase + ExportRva);
                return 1;
            }
        }

        ++SectionIndex;
    }

    return Result;
}
char EnumProcessPeExportData()
{
    char Result;
    __int64 Process;
    unsigned int GtIndex41B0;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int ComputedOffset;
    __int16 SectionType;
    unsigned int ExportRva;
    PE_DECODE_CONTEXT SectionContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 SectionFileOffset;
    ULONG SectionEntry[112];            // 描述符：原 [20] 仅 80 字节
    __int64 FieldValueSize;
    int FieldCount;
    int SectionDataSize;
    __int64 FieldFlags;
    unsigned int SectionAlignedSize;
    __int64 pSectionEntryBase;
    struct _KAPC_STATE ApcState;

    Result = 0;
    Process = GtRead(GtCurrentEprocess);  // 0x61 = 97

    if (Process)
        KeStackAttachProcess((struct _KPROCESS *)Process, &ApcState);

    GtIndex41B0 = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x41B0);  // 未命名偏移
    NtImageBase = GtRead(GtEprocessField22);    // 0x20 = 32
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);  // 0x21 = 33
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);  // 3
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);  // 2

    if (GtIndex41B0 &&
        GtIndex41B0 < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + GtIndex41B0),
            (ULONG)(NtImageSize - GtIndex41B0),
            2,
            0,
            -1,
            0,
            0,
            (__int64)&SectionContext);

        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
                break;

            ComputedOffset = SectionAlignedSize + (ULONG)SectionFileOffset;
            SectionFileOffset += SectionAlignedSize;
            SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

            if (SectionType == 0x545)
                break;

            if (SectionType == 0x512 &&
                FieldFlags == 0x40000 &&
                SectionDataSize &&
                FieldValueSize == 64 &&
                FieldCount == 1)
            {
                ExportRva = (unsigned int)(SectionDataSize - NtImageBase + (ULONG)ComputedOffset);
                if (ExportRva && ExportRva < NtImageSize)
                {
                    // 写入 GT 0x5F = GtEprocessField85
                    GtWrite(GtEprocessField85, NtoskrnlModuleBase + ExportRva);
                    Result = 1;
                    break;
                }
            }

            ++SectionIndex;
        }
    }

    if (Process)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}
char EnumProcessPeExportDataByIndex()
{
    char Result;
    __int64 Process;
    unsigned int GtIndex42DF;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int ComputedOffset;
    __int16 SectionType;
    unsigned int ExportRva;
    PE_DECODE_CONTEXT SectionContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 SectionFileOffset;
    ULONG SectionEntry[112];            // 描述符：原 [20] 仅 80 字节
    __int64 FieldFlags;
    __int64 FieldValueSize;
    int SectionDataSize;
    unsigned int SectionAlignedSize;
    __int64 pSectionEntryBase;
    struct _KAPC_STATE ApcState;

    Result = 0;
    Process = GtRead(GtCurrentEprocess);  // 0x61 = 97

    if (Process)
        KeStackAttachProcess((struct _KPROCESS *)Process, &ApcState);

    GtIndex42DF = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x42DF);  // 未命名偏移
    NtImageBase = GtRead(GtEprocessField22);    // 0x20 = 32
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);  // 0x21 = 33
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);  // 3
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);  // 2

    if (GtIndex42DF &&
        GtIndex42DF < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + GtIndex42DF),
            (ULONG)(NtImageSize - GtIndex42DF),
            2,
            0,
            -1,
            0,
            0,
            (__int64)&SectionContext);

        SectionIndex = 0;
        while (SectionIndex < 0xC8)
        {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
                break;

            ComputedOffset = SectionAlignedSize + (ULONG)SectionFileOffset;
            SectionFileOffset += SectionAlignedSize;
            SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

            if (SectionType == 0x545)
                break;

            if (SectionType == 0x50E &&
                FieldFlags == 0x40000 &&
                FieldValueSize == 0x40)
            {
                ExportRva = (unsigned int)(SectionDataSize - NtImageBase + (ULONG)ComputedOffset);
                if (ExportRva && ExportRva < NtImageSize)
                {
                    // 写入 GT 0x2BB = GtKernelDataField41
                    GtWrite(GtKernelDataField41, NtoskrnlModuleBase + ExportRva);
                    Result = 1;
                    break;
                }
            }

            ++SectionIndex;
        }
    }

    if (Process)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}
char EnumProcessPeExportDataEx()
{
    __int64 Process;
    unsigned int GtIndex43AB;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int ComputedOffset;
    __int16 SectionType;
    unsigned int ExportRva;
    PE_DECODE_CONTEXT SectionContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 SectionFileOffset;
    ULONG SectionEntry[112];            // 描述符：原 [20] 仅 80 字节
    __int64 FieldFlags;
    __int64 FieldValueSize;
    int FieldCount;
    int SectionDataSize;
    unsigned int SectionAlignedSize;
    __int64 pSectionEntryBase;
    struct _KAPC_STATE ApcState;
    char IsMarked;

    Process = GtRead(GtCurrentEprocess);  // 0x61 = 97

    if (Process)
        KeStackAttachProcess((struct _KPROCESS *)Process, &ApcState);

    GtIndex43AB = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43AB);  // 未命名偏移
    NtImageBase = GtRead(GtEprocessField22);    // 0x20 = 32
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);  // 0x21 = 33
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);  // 3
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);  // 2

    if (!GtIndex43AB ||
        GtIndex43AB >= NtImageSize ||
        !NtImageBase ||
        !NtImageSize ||
        !NtoskrnlModuleBase ||
        !NtoskrnlImageSize)
    {
        if (Process)
            KeUnstackDetachProcess(&ApcState);
        return 0;
    }

    InitPESectionReadContext(
        (__int64)(NtImageBase + GtIndex43AB),
        (ULONG)(NtImageSize - GtIndex43AB),
        2,
        0,
        -1,
        0,
        0,
        (__int64)&SectionContext);

    IsMarked = 0;
    SectionIndex = 0;
    while (SectionIndex < 0x190)
    {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            break;

        ComputedOffset = SectionAlignedSize + (ULONG)SectionFileOffset;
        SectionFileOffset += SectionAlignedSize;
        SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        // 检查 Type 是否在 0x53C-0x543 范围内
        if ((unsigned int)(SectionType - 0x53C) <= 7)
        {
            if (FieldFlags == 0x800000 &&
                FieldCount == 0x4EC4EC4F)
            {
                IsMarked = 1;
                ++SectionIndex;
                continue;
            }
        }

        // 检查 Type 0x512
        if (SectionType == 0x512 &&
            FieldFlags == 0x40000 &&
            FieldValueSize == 64 &&
            IsMarked)
        {
            ExportRva = (unsigned int)(SectionDataSize - NtImageBase + (ULONG)ComputedOffset);
            if (ExportRva && ExportRva < NtImageSize)
            {
                // 写入 GT 0x338 = GtCallbackField103
                GtWrite(GtCallbackField103, NtoskrnlModuleBase + ExportRva);
                if (Process)
                    KeUnstackDetachProcess(&ApcState);
                return 1;
            }
        }

        ++SectionIndex;
    }

    if (Process)
        KeUnstackDetachProcess(&ApcState);

    return 0;
}
char __fastcall ValidateWin32kBaseDriverImage(__int64 DiskBuffer, unsigned int DiskSize)
{
    unsigned int Result;
    __int64 ImageBase;
    unsigned int ImageSize;

    Result = (unsigned int)GtRead(GtFwpsDispatchTableBase);
    if (!Result)
    {
        ImageBase = GtRead(GtHalModuleBase);
        ImageSize = (unsigned int)GtRead(GtFwpsDispatchTableCount);

        if (ImageBase && ImageSize && DiskBuffer && DiskSize && ImageSize > 0x1000)
        {
            GtWrite(GtFwpsDispatchTableBase, 1);
            if (ComparePeHeaders(ImageBase, ImageSize, DiskBuffer, DiskSize) == 1)
                GtWrite(GtFwpsDispatchTableCount, 1);
        }

        Result = ImageSize;
    }

    return (char)Result;
}
__int64 __fastcall BtreeInsertExportEntry(unsigned __int8 *Name, int Ordinal, unsigned int Key)
{
    __int64 CurrentNode;
    __int64 *RootPtr;
    __int64 *CurrentPtr;
    unsigned int NodeKey;
    char *NamePtr;
    char CurrentChar;
    __int64 result;
    __int64 *TreeRoot;
    __int64 NewNode;

    CurrentNode = 0;
    RootPtr = GtAlloc((enum _GLOBAL_TABLE_INDEX)(*Name + 109));
    CurrentPtr = RootPtr;
    while (*CurrentPtr)
    {
        CurrentNode = *CurrentPtr;
        NodeKey = *(unsigned int *)(CurrentNode + 32);
        if (NodeKey == Key)
        {
            NamePtr = (char *)(CurrentNode + 36);
            while (1)
            {
                CurrentChar = *NamePtr;
                if (*NamePtr != Name[(_QWORD)NamePtr])
                    break;
                ++NamePtr;
                if (!CurrentChar)
                {
                    result = 0;
                    goto LABEL_10;
                }
            }
            result = (unsigned __int8)*NamePtr < Name[(_QWORD)NamePtr] ? -1 : 1;
        }
        else
        {
            if (NodeKey > Key)
                goto LABEL_13;
            result = -1LL;
        }
    LABEL_10:
        if ((int)result <= 0)
        {
            if ((int)result >= 0)
                return result;
            CurrentPtr = (__int64 *)(CurrentNode + 24);
            continue;
        }
    LABEL_13:
        CurrentPtr = (__int64 *)(CurrentNode + 16);
    }
    TreeRoot = GtAlloc(GtEprocessField99 | 0x100);
    result = (__int64)BtreeBufferAllocator(TreeRoot, 0x68, 0x80000);
    NewNode = result;
    if (result)
    {
        *(unsigned int *)(result + 100) = Ordinal;
        *(unsigned int *)(result + 32) = Key;
        StringCopy((_BYTE *)(result + 36), (__int64)Name, 0x40);
        *(_BYTE *)(NewNode + 99) = 0;
        *(_DWORD *)NewNode = 0;
        *(_QWORD *)(NewNode + 16) = 0;
        *(_QWORD *)(NewNode + 24) = 0;
        *(_QWORD *)(NewNode + 8) = CurrentNode;
        *CurrentPtr = NewNode;
        return (__int64)RBTreeInsertFixup(NewNode, RootPtr);
    }
    return result;
}
_DWORD *__fastcall BtreeBufferAllocator(__int64 *pAllocator, unsigned int RequestSize, unsigned int BlockSize)
{
    __int64 Size;
    __int64 AllocSize;
    _DWORD *result;
    unsigned int RemainingSize;
    __int64 pBlock;
    __int64 pCurrentPos;
    int AdjustedSize;

    Size = RequestSize;
    if (!*pAllocator || *(_DWORD *)(*pAllocator + 28) < RequestSize)
    {
        AllocSize = BlockSize;
        result = ExAlloc(PagedPool, BlockSize);
        if (!result)
            return result;
        result[6] = BlockSize;
        RemainingSize = BlockSize - 40;
        *(_QWORD *)result = (_QWORD)(result + 10);
        *((_QWORD *)result + 2) = (_QWORD)(result + 10);
        result[7] = RemainingSize;
        *((_QWORD *)result + 1) = (_QWORD)((char *)result + AllocSize);
        if ((((ULONG_PTR)result + 40) & 3) != 0)
        {
            result[7] = (((ULONG_PTR)result + 40) & 3) + RemainingSize - 4;
            *((_QWORD *)result + 2) = (_QWORD)((char *)result - (((ULONG_PTR)result + 40) & 3) + 44);
        }
        *((_QWORD *)result + 4) = *pAllocator;
        *pAllocator = (__int64)result;
    }
    pBlock = *pAllocator;
    pCurrentPos = *(_QWORD *)(*pAllocator + 16);
    *(_DWORD *)(pBlock + 28) -= (unsigned int)Size;
    AdjustedSize = *(_DWORD *)(pBlock + 28);
    *(_QWORD *)(pBlock + 16) = pCurrentPos + Size;
    if (((ULONG_PTR)pCurrentPos + Size & 3) != 0)
    {
        *(_DWORD *)(pBlock + 28) = ((ULONG_PTR)pCurrentPos + Size & 3) + AdjustedSize - 4;
        *(_QWORD *)(pBlock + 16) = pCurrentPos + Size - ((ULONG_PTR)pCurrentPos + Size & 3) + 4;
    }
    return (_DWORD *)pCurrentPos;
}
__int64 __fastcall RBTreeRotateLeft(__int64 Node, _QWORD *Root)
{
    __int64 ParentNode;
    __int64 ChildNode;
    __int64 result;

    ParentNode = *(_QWORD *)(Node + 24);
    ChildNode = *(_QWORD *)(ParentNode + 16);
    *(_QWORD *)(Node + 24) = ChildNode;
    if (ChildNode)
        *(_QWORD *)(*(_QWORD *)(ParentNode + 16) + 8) = Node;
    *(_QWORD *)(ParentNode + 16) = Node;
    result = *(_QWORD *)(Node + 8);
    *(_QWORD *)(ParentNode + 8) = result;
    if (result)
    {
        result = *(_QWORD *)(Node + 8);
        if (Node == *(_QWORD *)(result + 16))
            *(_QWORD *)(result + 16) = ParentNode;
        else
            *(_QWORD *)(result + 24) = ParentNode;
    }
    else
    {
        *Root = ParentNode;
    }
    *(_QWORD *)(Node + 8) = ParentNode;
    return result;
}
__int64 __fastcall RBTreeRotateRight(__int64 Node, _QWORD *Root)
{
    __int64 ParentNode;
    __int64 ChildNode;
    __int64 result;

    ParentNode = *(_QWORD *)(Node + 16);
    ChildNode = *(_QWORD *)(ParentNode + 24);
    *(_QWORD *)(Node + 16) = ChildNode;
    if (ChildNode)
        *(_QWORD *)(*(_QWORD *)(ParentNode + 24) + 8) = Node;
    *(_QWORD *)(ParentNode + 24) = Node;
    result = *(_QWORD *)(Node + 8);
    *(_QWORD *)(ParentNode + 8) = result;
    if (result)
    {
        result = *(_QWORD *)(Node + 8);
        if (Node == *(_QWORD *)(result + 24))
            *(_QWORD *)(result + 24) = ParentNode;
        else
            *(_QWORD *)(result + 16) = ParentNode;
    }
    else
    {
        *Root = ParentNode;
    }
    *(_QWORD *)(Node + 8) = ParentNode;
    return result;
}
_DWORD *__fastcall RBTreeInsertFixup(__int64 NewNode, _QWORD *Root)
{
    __int64 CurrentNode;
    __int64 TargetNode;
    __int64 SiblingNode;
    _DWORD *UncleNode;
    __int64 TempNode;
    __int64 TempNode2;
    _DWORD *result;

    CurrentNode = *(_QWORD *)(NewNode + 8);
    TargetNode = NewNode;
    while (CurrentNode && !*(_DWORD *)CurrentNode)
    {
        SiblingNode = *(_QWORD *)(CurrentNode + 8);
        UncleNode = *(_DWORD **)(SiblingNode + 16);
        if ((_DWORD *)CurrentNode == UncleNode)
        {
            UncleNode = *(_DWORD **)(SiblingNode + 24);
            if (UncleNode && !*UncleNode)
                goto LABEL_6;
            if (*(_QWORD *)(CurrentNode + 24) == TargetNode)
            {
                RBTreeRotateLeft(CurrentNode, Root);
                TempNode = CurrentNode;
                CurrentNode = TargetNode;
                TargetNode = TempNode;
            }
            *(_DWORD *)CurrentNode = 1;
            *(_DWORD *)SiblingNode = 0;
            RBTreeRotateRight(SiblingNode, Root);
        }
        else
        {
            if (UncleNode && !*UncleNode)
            {
    LABEL_6:
                *UncleNode = 1;
                *(_DWORD *)CurrentNode = 1;
                *(_DWORD *)SiblingNode = 0;
                TargetNode = SiblingNode;
                goto LABEL_15;
            }
            if (*(_QWORD *)(CurrentNode + 16) == TargetNode)
            {
                RBTreeRotateRight(CurrentNode, Root);
                TempNode2 = CurrentNode;
                CurrentNode = TargetNode;
                TargetNode = TempNode2;
            }
            *(_DWORD *)CurrentNode = 1;
            *(_DWORD *)SiblingNode = 0;
            RBTreeRotateLeft(SiblingNode, Root);
        }
    LABEL_15:
        CurrentNode = *(_QWORD *)(TargetNode + 8);
    }
    result = (_DWORD *)*Root;
    *(_DWORD *)*Root = 1;
    return result;
}
char __fastcall CheckExportNamePrefixWin10(_BYTE *pBuffer1, char *pBuffer2, unsigned int CompareSize)
{
    char Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563 && CompareSize >= 0xC)
        Result = ScanPESectionPatterns(pBuffer1, pBuffer2, 12, 1) == 1;
    return Result;
}
