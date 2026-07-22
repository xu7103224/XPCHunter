# -*- coding: utf-8 -*-
import sys

def append_to_file(filepath, content):
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(content)
    print(f'Written to {filepath}')

# ModuleMgmt.c functions
module_content = """

// FindKernelDataSectionOffsetWin8 -- 查找内核数据节区偏移（Win8+ 版本）。
// 遍历 PE 节区，先记录 Type 1296(0x510) 且 SectionCharacteristics==0x40000 的偏移，
// 再查找 Type 1298(0x512) 且偏移匹配的节区，结果写入 GT 0x821。
// 对应原始驱动 sub_140042EE8
__int64 FindKernelDataSectionOffsetWin8(void)
{
    __int64 NtImageBase = GtRead(GtEprocessField22);
    unsigned int NtImageSize = GtRead(GtEprocessField23);
    __int64 NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    __int64 result = GtRead(GtTotalSize | GtEprocessExtField54 | GtEprocessField54);
    if (NtImageBase && NtImageSize && NtoskrnlImageBase && (_DWORD)result && (unsigned int)result < NtImageSize)
    {
        __int64 SectionContext;
        __int64 AccumulatedOffset;
        _DWORD SectionEntry[30];
        unsigned int RawDataSize;
        __int64 SectionCharacteristics;
        unsigned int SectionFileOffset;
        __int64 pSectionEntryBase;

        InitPESectionReadContext(
            NtImageBase + (unsigned int)result,
            NtImageSize - result,
            2, 0, -1, 0, 0,
            (__int64)&SectionContext);
        int SectionOffset = 0;
        for (unsigned int SectionIndex = 0; SectionIndex < 0x64; ++SectionIndex)
        {
            result = ReadPESectionEntry(&SectionContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int ComputedOffset = SectionFileOffset + AccumulatedOffset;
            AccumulatedOffset += SectionFileOffset;
            __int16 SectionType = *(_WORD *)(pSectionEntryBase + 6);
            result = RawDataSize;
            if (SectionType == 1296 && SectionCharacteristics == 0x40000 && RawDataSize)
            {
                SectionOffset = ComputedOffset + RawDataSize - NtImageBase;
            }
            else if (SectionType == 1298 && SectionCharacteristics == 0x40000)
            {
                if (RawDataSize)
                {
                    result = ComputedOffset + RawDataSize - (unsigned int)NtImageBase;
                    if ((_DWORD)result)
                    {
                        if ((unsigned int)result < NtImageSize && SectionOffset == (_DWORD)result)
                            return GtWrite(GtFwpsDispatchTableCount | GtEprocessField22, NtoskrnlImageBase + (unsigned int)result);
                    }
                }
            }
        }
    }
    return result;
}
"""

append_to_file('src/ModuleMgmt.c', module_content)

# ProcessMgmt.c functions
process_content = """

// BuildExportServiceTable -- 构建导出服务表。
// 读取用户态 DLL（win32k/其他），解析导出目录，构建服务表到缓冲区。
// 对应原始驱动 sub_1400063E0
char BuildExportServiceTable(
    __int64 ImageBase,
    struct _KPROCESS *TargetProcess,
    char Is64Bit,
    _QWORD *OutServiceTable)
{
    char Success = 0;
    unsigned int ServiceCount = GtRead(GtWin32kServiceCount);
    unsigned int ModuleEntrySize;
    __int64 *RelocAllocBuffer;
    int IsWin32k;
    if (Is64Bit)
    {
        ModuleEntrySize = GtRead(GtWin32kServiceTableSize64);
        RelocAllocBuffer = GtAlloc(GtWin32kServiceBuffer64);
        IsWin32k = 1;
    }
    else
    {
        ModuleEntrySize = GtRead(GtWin32kServiceTableSize32);
        RelocAllocBuffer = GtAlloc(GtWin32kServiceBuffer32);
        IsWin32k = 0;
    }
    __int64 *RelocBuffer = RelocAllocBuffer;
    __int64 ImageBaseLocal;
    __int64 RelocStatArray[9];
    void *RelocTableData;
    ULONG64 ModuleBaseAddr = ParseNtRelocationTable(
        TargetProcess, Is64Bit, &ImageBaseLocal,
        RelocStatArray, &RelocTableData);
    if (ModuleBaseAddr && ServiceCount && ModuleEntrySize && RelocBuffer && ImageBaseLocal)
    {
        char *User32Buffer;
        unsigned int FileSize;
        if (ReadUser32DllFile(&User32Buffer, &FileSize, Is64Bit))
        {
            ULONG64 ModuleBase = ModuleBaseAddr;
            if (ParseNtExportDir((__int64)User32Buffer, FileSize, ModuleBaseAddr, IsWin32k) == 1)
            {
                unsigned int *ExportEntry = (unsigned int *)RelocBuffer + 1;
                __int64 ServiceCount2 = ServiceCount;
                do
                {
                    *(ExportEntry - 1) = 0;
                    if (*ExportEntry < FileSize && *ExportEntry + 16 <= FileSize)
                    {
                        *(ExportEntry - 1) = 1;
                        *(_OWORD *)(ExportEntry + 3) = *(_OWORD *)&User32Buffer[*ExportEntry];
                    }
                    ExportEntry += 12;
                    --ServiceCount2;
                }
                while (ServiceCount2);
            }
            ExFree(User32Buffer);
        }
        ULONG64 ModuleBase = ModuleBaseAddr;
        ULONG64 FuncTableAddr = ModuleBase + ModuleEntrySize;
        OutServiceTable[1] = ImageBaseLocal;
        OutServiceTable[3] = RelocStatArray[0];
        OutServiceTable[2] = FuncTableAddr;
        unsigned int ServiceIndex = 0;
        int LoopIndex = 0;
        while (ServiceIndex < ServiceCount)
        {
            OutServiceTable[9 * ServiceIndex + 8] = ServiceIndex;
            __int64 FuncValue;
            ULONG64 FuncAddrPtr;
            if (Is64Bit)
            {
                FuncValue = *(unsigned int *)((char*)RelocTableData + 4LL * ServiceIndex);
                FuncAddrPtr = FuncTableAddr + 4LL * ServiceIndex;
            }
            else
            {
                FuncValue = *(_QWORD *)((char*)RelocTableData + 8LL * ServiceIndex);
                FuncAddrPtr = FuncTableAddr + 8LL * ServiceIndex;
            }
            OutServiceTable[9 * ServiceIndex + 10] = FuncValue;
            OutServiceTable[9 * ServiceIndex + 7] = FuncAddrPtr;
            OutServiceTable[9 * ServiceIndex + 5] = TargetProcess;
            OutServiceTable[9 * ServiceIndex + 6] = ImageBase;
            OutServiceTable[9 * ServiceIndex + 9] = ModuleBase + HIDWORD(RelocBuffer[6 * ServiceIndex]);
            ++ServiceIndex;
        }
        Success = 1;
    }
    if (ModuleBaseAddr)
        ExFree(RelocTableData);
    return Success;
}
"""

append_to_file('src/ProcessMgmt.c', process_content)