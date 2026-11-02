// Utility.c — 通用工具函数集合

#include "XPCHunterDrv.h"

// StringLength — 获取ANSI字符串长度
__int64 __fastcall ProcessDiskSectorData(__int64, __int64, __int64, unsigned int);
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 对应原始驱动 sub_14007D7E8
__int64 StringLength(_BYTE *String)
{
    __int64 Result = 0;
    if (*String)
    {
        do
            Result = (unsigned int)(Result + 1);
        while (String[Result]);
    }
    return Result;
}

// MemoryCompare — 内存比较
// 对应原始驱动 sub_14007D754
unsigned int MemoryCompare(__int64 Buf1, char *Buf2, unsigned int Size)
{
    unsigned int Result = 0;
    unsigned int Index = 0;

    if (Size)
    {
        __int64 Delta = Buf1 - (__int64)Buf2;
        do
        {
            Result = (unsigned char)(Buf2[Delta] - *Buf2);
            if ((int)Result)
                break;
            ++Index;
            ++Buf2;
        }
        while (Index < Size);
    }
    return Result;
}

// StringCompare — 字符串比较
// 对应原始驱动 sub_14007D77C
__int64 StringCompare(__int64 Str1, __int64 Str2)
{
    __int64 Index = 0;
    int Char2;
    __int64 Result;

    do
    {
        Char2 = *(char *)(Index + Str2);
        Result = (unsigned int)(*(char *)(Index + Str1) - Char2);
        if (!*(_BYTE *)(Index + Str1))
            break;
        if (!(_BYTE)Char2)
            break;
        Index = (unsigned int)(Index + 1);
    }
    while (!(_DWORD)Result);
    return Result;
}

// StringCopy — 字符串复制
// 对应原始驱动 sub_14007D7F8
_BYTE *StringCopy(_BYTE *Dest, __int64 Src, unsigned int MaxLen)
{
    unsigned int Index = 0;
    _BYTE *DestPtr;
    __int64 Delta;

    if (MaxLen)
    {
        DestPtr = Dest;
        Delta = Src - (__int64)Dest;
        do
        {
            _BYTE Ch = DestPtr[Delta];
            *DestPtr = Ch;
            if (!Ch)
                break;
            ++Index;
            ++DestPtr;
        }
        while (Index < MaxLen);
    }
    return Dest;
}

// StringCompareCaseInsensitiveV2 — 字符串不区分大小写比较V2
// 对应原始驱动 sub_14007D7A4
__int64 StringCompareCaseInsensitiveV2(__int64 Str1, __int64 Str2)
{
    __int64 Index;
    char Ch1;
    char Ch2;

    for (Index = 0; ; Index = (unsigned int)(Index + 1))
    {
        Ch1 = *(_BYTE *)(Index + Str1);
        if ((unsigned char)(Ch1 - 97) <= 0x19u)
            Ch1 -= 32;
        Ch2 = *(_BYTE *)(Index + Str2);
        if ((unsigned char)(Ch2 - 97) <= 0x19u)
            Ch2 -= 32;
        if (Ch1 > Ch2 || Ch1 < Ch2)
            break;
        if (!Ch1)
            return 0;
    }
    return (unsigned int)(Ch1 - Ch2);
}

// StringCompareCaseInsensitive — 字符串不区分大小写比较
// 对应原始驱动 sub_14007D820
__int64 StringCompareCaseInsensitive(__int64 Str1, char *Str2, unsigned int MaxLen)
{
    unsigned int Index = 0;
    char *Str2Ptr;
    __int64 Delta;
    char Ch1;
    char Ch2;

    Index = 0;
    Str2Ptr = Str2;
    if (!MaxLen)
        return 0;
    Delta = Str1 - (__int64)Str2;
    while (1)
    {
        Ch1 = Str2Ptr[Delta];
        if ((unsigned char)(Ch1 - 97) <= 0x19u)
            Ch1 -= 32;
        Ch2 = *Str2Ptr;
        if ((unsigned char)(*Str2Ptr - 97) <= 0x19u)
            Ch2 -= 32;
        if (Ch1 > Ch2 || Ch1 < Ch2)
            break;
        if (Ch2)
        {
            ++Index;
            ++Str2Ptr;
            if (Index < MaxLen)
                continue;
        }
        return 0;
    }
    return (unsigned int)(Ch1 - Ch2);
}

// StringCompare3Way — 字符串三路比较（不区分大小写，比较宽字符串）
// 对应原始驱动 sub_14007DA0C
__int64 StringCompare3Way(__int64 Str1, unsigned __int16 *Str2, unsigned int MaxLen)
{
    unsigned __int16 *Str2Ptr;
    unsigned int Index;
    __int64 Delta;
    unsigned __int16 Ch1;
    unsigned __int16 Ch2;

    Str2Ptr = Str2;
    Index = 0;
    if (!MaxLen)
        return 0;
    Delta = Str1 - (__int64)Str2;
    while (1)
    {
        Ch1 = *(unsigned __int16 *)((char *)Str2Ptr + Delta);
        if ((unsigned __int16)(Ch1 - 97) <= 0x19u)
            Ch1 -= 32;
        Ch2 = *Str2Ptr;
        if ((unsigned __int16)(*Str2Ptr - 97) <= 0x19u)
            Ch2 -= 32;
        if (Ch1 > Ch2)
            break;
        if (Ch1 < Ch2)
            return 0xFFFFFFFFLL;
        if (Ch1)
        {
            ++Index;
            ++Str2Ptr;
            if (Index < MaxLen)
                continue;
        }
        return 0;
    }
    return 1;
}

// GetStringLength — 获取宽字符串长度
// 对应原始驱动 sub_14007D924
__int64 GetStringLength(_WORD *String)
{
    __int64 Result = 0;
    if (*String)
    {
        do
            Result = (unsigned int)(Result + 1);
        while (String[Result]);
    }
    return Result;
}

// WStringCopy — 宽字符串复制
// 对应原始驱动 sub_14007D89C
__int16 *WStringCopy(__int16 *Dest, __int16 *Src)
{
    __int16 FirstChar = *Src;
    unsigned int Index = 0;
    __int16 NextChar;

    *Dest = *Src;
    if (FirstChar)
    {
        do
        {
            Index = (unsigned int)(Index + 1);
            NextChar = Src[Index];
            Dest[Index] = NextChar;
        }
        while (NextChar);
    }
    return Dest;
}

// WStringCopyN — 宽字符串复制（带长度限制）
// 对应原始驱动 sub_14007D9DC
_WORD *WStringCopyN(_WORD *Dest, __int64 Src, unsigned int MaxLen)
{
    unsigned int Index = 0;
    _WORD *DestPtr;
    __int64 Delta;

    if (MaxLen)
    {
        DestPtr = Dest;
        Delta = Src - (__int64)Dest;
        do
        {
            __int16 Ch = *(_WORD *)((char *)DestPtr + Delta);
            *DestPtr = Ch;
            if (!Ch)
                break;
            ++Index;
            ++DestPtr;
        }
        while (Index < MaxLen);
    }
    return Dest;
}

// WStringCompareCaseInsensitive — 宽字符串不区分大小写比较
// 对应原始驱动 sub_14007D8C8
__int64 WStringCompareCaseInsensitive(__int64 Str1, __int64 Str2)
{
    unsigned int Index;
    unsigned __int16 Ch1;
    unsigned __int16 Ch2;

    for (Index = 0; ; ++Index)
    {
        Ch1 = *(_WORD *)(Str1 + 2LL * Index);
        if ((unsigned __int16)(Ch1 - 97) <= 0x19u)
            Ch1 -= 32;
        Ch2 = *(_WORD *)(Str2 + 2LL * Index);
        if ((unsigned __int16)(Ch2 - 97) <= 0x19u)
            Ch2 -= 32;
        if (Ch1 > Ch2 || Ch1 < Ch2)
            break;
        if (!Ch1)
            return 0;
    }
    return Ch1 - (unsigned int)Ch2;
}

// WStringCompare — 宽字符串比较
// 对应原始驱动 sub_14007D99C
__int64 WStringCompare(__int64 Str1, unsigned __int16 *Str2, unsigned int MaxLen)
{
    unsigned int Index = 0;
    __int64 Delta;
    unsigned __int16 Ch1;
    unsigned __int16 Ch2;

    if (!MaxLen)
        return 0;
    Delta = Str1 - (__int64)Str2;
    while (1)
    {
        Ch1 = *(unsigned __int16 *)((char *)Str2 + Delta);
        Ch2 = *Str2;
        if (Ch1 > Ch2 || Ch1 < Ch2)
            break;
        if (Ch1)
        {
            ++Index;
            ++Str2;
            if (Index < MaxLen)
                continue;
        }
        return 0;
    }
    return Ch1 - (unsigned int)Ch2;
}

// WStringConcat — 宽字符串连接
// 对应原始驱动 sub_14007D93C
_WORD *WStringConcat(_WORD *Dest, __int16 *Src, unsigned int MaxLen)
{
    unsigned int DestLen = 0;
    unsigned int Index;

    if (*Dest)
    {
        do
            DestLen = (unsigned int)(DestLen + 1);
        while (Dest[DestLen]);
    }
    for (Index = 0; Index < MaxLen; Dest[DestLen + Index] = *Src)
    {
        __int16 SrcChar = *Src;
        if (!*Src)
            break;
        ++Index;
        ++Src;
    }
    Dest[DestLen + Index] = 0;
    return Dest;
}

// WStringFindChar — 宽字符串查找字符
// 对应原始驱动 sub_14007D870
__int16 *WStringFindChar(__int16 *String, __int16 Char)
{
    __int16 CurrentChar = *String;
    __int64 Result = 0;
    int Index = 0;

    while (Char != CurrentChar)
    {
        if (!CurrentChar)
            return (__int16 *)Result;
        CurrentChar = String[++Index];
    }
    return &String[Index];
}

// WStringFindLastChar — 宽字符串查找最后一个字符
// 对应原始驱动 sub_14007DA74
_WORD *WStringFindLastChar(_WORD *String, __int16 Char)
{
    __int64 Result = 0;
    unsigned int Len = 0;

    if (*String)
    {
        do
            Len = (unsigned int)(Len + 1);
        while (String[Len]);
        if ((int)Len)
        {
            int Index = Len - 1;
            __int64 Index64 = Len - 1;
            if (Len - 1 >= 0)
            {
                while (Char != String[Index64])
                {
                    --Index;
                    if (--Index64 < 0)
                        return (_WORD *)Result;
                }
                return &String[Index];
            }
        }
    }
    return (_WORD *)Result;
}

// CheckTmDllSection — 检查 TM DLL 节区
// 验证 ext-ms-win-ntos-tm-l1-1-0.dll 的 PE 节区头信息
// 对应原始驱动 sub_1400828A0
char CheckTmDllSection(unsigned __int8 *NameToMatch)
{
    char Result;
    __int64 FileBuffer;
    unsigned int FileSize;
    unsigned int Offset;
    _WORD NameBuffer[32];

    Result = 0;
    wcscpy((wchar_t *)NameBuffer, L"ext-ms-win-ntos-tm-l1-1-0.dll");
    NameBuffer[15] = 0;
    FileBuffer = GtRead(GtEprocessField22);
    FileSize = (unsigned int)GtRead(GtEprocessField23);
    if (FileSize && FileBuffer)
        return ParsePESectionHeaders(FileBuffer, FileSize, (__int64)NameBuffer, NameToMatch, &Offset) == 1;
    return Result;
}


// ReadNtFileDiskInfo — 读取磁盘信息 NT 驱动文件
// 对应原始驱动 sub_14004997C
char ReadNtFileDiskInfo(void **OutBuffer, unsigned int *OutSize)
{
    char Result;
    size_t MaxCount;
    void *Src;
    int EncodedPath[18];
    __int64 ExtraPathPart;

    Result = 0;
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
    EncodedPath[14] = 5505116;
    EncodedPath[15] = 7340131;
    EncodedPath[16] = 7340137;
    EncodedPath[17] = 7536686;
    ExtraPathPart = 7536761;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)OutBuffer, OutSize) == 1;
        ExFree(Src);
    }
    return Result;
}


// ReadNtFileForProcessContext — 读取 ntoskrnl 文件用于进程上下文
// 对应原始驱动 sub_1400322D8
char ReadNtFileForProcessContext(_QWORD *OutBuffer, unsigned int *OutSize)
{
    char Result;
    size_t MaxCount;
    void *Src;
    int EncodedPath[17];
    __int64 ExtraPathPart;

    Result = 0;
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
    EncodedPath[14] = 6357084;
    EncodedPath[15] = 6553702;
    EncodedPath[16] = 7536686;
    ExtraPathPart = 7536761;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)OutBuffer, OutSize) == 1;
        ExFree(Src);
    }
    return Result;
}


// ReadNtoskrnlToBuffer — 读取 ntoskrnl 到缓冲区
// 对应原始驱动 sub_140039A8C
char ReadNtoskrnlToBuffer(void **OutBuffer, unsigned int *OutSize)
{
    char Result;
    size_t RawDataSize;
    void *pRawData;
    int EncodedPath[21];

    Result = 0;
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
    EncodedPath[15] = 6684784;
    EncodedPath[16] = 7602284;
    EncodedPath[17] = 7471204;
    EncodedPath[18] = 3014774;
    EncodedPath[19] = 7929971;
    EncodedPath[20] = 115;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &pRawData, (ULONG *)&RawDataSize, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)pRawData, (unsigned int)RawDataSize, (PUCHAR *)OutBuffer, OutSize) == 1;
        ExFree(pRawData);
    }
    return Result;
}


// GetCurrentFiber — 获取当前处理器控制块 (PRCB) 指针，实为 KeGetCurrentPrcb() 封装
// 对应原始驱动 sub_140001584
PVOID GetCurrentFiber(void)
{
    return (PVOID)__readgsqword(0x20);
}


// ReadProcessMemoryString — 读取进程内存字符串
// 处理进程内存字符串读取请求：从 40 字节输入缓冲区解析目标地址和参数，
// 分配 0x10000 字节交换缓冲区，通过 GtReadMemoryFunc 读取内核内存，
// 支持分页读取和内核内存交换处理
// 对应原始驱动 sub_140074418 (CmdReadProcessMemoryStr)
__int64 ReadProcessMemoryString(void *InputBuffer, int InputSize, void *OutputBuffer, unsigned int OutputSize)
{
    char Result = 0;
    void *SwapBuffer = NULL;
    char ReadyFlag = 0;
    char InputByte0;
    char ModeFlag;
    unsigned int Temp;
    __int64 TargetAddress;
    void *OutputParam;
    __int64 ReadFunc;
    __int64 AltReadFunc;
    unsigned int CurrentPage;
    unsigned int EndFlag;
    unsigned int *pCurrentOutput;
    unsigned int OutputOffset;
    unsigned int WrittenSize;
    int BytesRead;
    int LoopsWithoutProgress;
    unsigned int PrevModeOffset;
    unsigned char SavedPrevMode;

    if (!InputBuffer
        || InputSize != 40
        || !OutputBuffer
        || OutputSize <= 0x10
        || (unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)((char *)InputBuffer + 40) >= MmUserProbeAddress
        || (unsigned __int64)OutputBuffer >= MmUserProbeAddress
        || (unsigned __int64)((char *)OutputBuffer + OutputSize) >= MmUserProbeAddress)
    {
        return 0;
    }

    ProbeForRead(InputBuffer, 0x28u, 1u);
    ProbeForWrite(OutputBuffer, OutputSize, 1u);

    InputByte0 = *(char *)InputBuffer;
    ModeFlag = *((char *)InputBuffer + 1);
    ReadyFlag = 0;

    if (InputByte0 == 1)
    {
        Temp = *(unsigned int *)((char *)InputBuffer + 4);
        if (Temp > 2)
        {
            TargetAddress = *(__int64 *)((char *)InputBuffer + 8);
            if (TargetAddress
                && (unsigned __int64)TargetAddress < MmUserProbeAddress
                && (unsigned __int64)Temp < MmUserProbeAddress
                && (unsigned __int64)(TargetAddress + Temp) < MmUserProbeAddress)
            {
                ProbeForRead((void *)TargetAddress, Temp, 1u);
                if (*(unsigned short *)(TargetAddress + 2 * (((unsigned int)Temp - 2) >> 1)))
                    *(unsigned short *)(TargetAddress + 2 * (((unsigned int)Temp - 2) >> 1)) = 0;
                SwapBuffer = ExAlloc(PagedPool, 0x10000u);
                if (SwapBuffer)
                    ReadyFlag = 1;
            }
        }
    }
    else
    {
        ReadyFlag = 1;
    }

    if (ReadyFlag == 1)
    {
        OutputParam = *(void **)((char *)InputBuffer + 32);
        if (OutputParam
            && (unsigned __int64)OutputParam < MmUserProbeAddress
            && (unsigned __int64)((char *)OutputParam + 4) < MmUserProbeAddress)
        {
            ProbeForWrite(OutputParam, 4u, 4u);

            // 【重构 2026-09-21】按原始驱动结构补回对 SendReadMemoryIoControl 的委托调用。
            //   原始 CmdReadProcessMemoryStr 在 ProbeForWrite 之后调用它（伪代码 115 行），
            //   并**仅在「返回 0 且出标志 == 1」时**才进入后续处理（伪代码 127 行）。
            //   此前复刻把后续处理无条件内联、且整体跳过了这次调用，导致
            //   SendReadMemoryIoControl 与其内层调用的 SendIoControlWithBufferSwap
            //   虽已实现却不可达（map 中无它们）。
            //   11 个实参全部由调用方伪代码定案：v5 = 第 3 形参(输出缓冲)、
            //   v8 = ExAlloc(PagedPool, 0x10000)、v35 = 0x10000、
            //   v48 = *(BYTE*)Address（即下方的 InputByte0）。
            {
                char CallFlag = 0;
                __int64 CallResult;

                CallResult = SendReadMemoryIoControl(
                    (unsigned char *)&CallFlag,
                    *(__int64 *)((char *)InputBuffer + 0x10),
                    (unsigned char)(*(__int64 *)((char *)InputBuffer + 0x30)),
                    (unsigned int)(*(__int64 *)((char *)InputBuffer + 0x38)),
                    (unsigned char *)OutputBuffer,
                    OutputSize,
                    *(__int64 *)((char *)InputBuffer + 0x20),
                    (unsigned char)InputByte0,
                    (unsigned char *)InputBuffer,
                    (__int64)SwapBuffer,
                    0x10000);

                if (CallResult != 0 || CallFlag != 1)
                    goto LABEL_READ_STRING_CLEANUP;
            }

            TargetAddress = *(__int64 *)((char *)InputBuffer + 8);
            CurrentPage = *(unsigned int *)((char *)InputBuffer + 24);
            EndFlag = *(unsigned int *)((char *)InputBuffer + 28);
            ReadFunc = GtRead(GtReadMemoryFunc);

            if (ReadFunc && (unsigned int)GtRead(39) != -1)  // GtSdstServiceCount != -1
            {
                // 主路径：通过 GtReadMemoryFunc 读取内存
                PrevModeOffset = (unsigned int)GtRead(39);  // GtPrevModeOffset
                SavedPrevMode = *(unsigned char *)((char *)KeGetCurrentThread() + PrevModeOffset);
                *(unsigned char *)((char *)KeGetCurrentThread() + PrevModeOffset) = 0;

                pCurrentOutput = (unsigned int *)OutputBuffer;
                LoopsWithoutProgress = 0;
                OutputOffset = 0;

                while (1)
                {
                    BytesRead = (int)(((__int64 (__fastcall *)(__int64, unsigned int, unsigned int, unsigned int *, unsigned int, void *))ReadFunc)(
                        TargetAddress, CurrentPage, EndFlag, pCurrentOutput, OutputSize, OutputParam));

                    if (EndFlag)
                        break;

                    if (ModeFlag == 1)
                    {
                        *pCurrentOutput = 0;
                        if (!BytesRead && InputByte0 == 1)
                            pCurrentOutput[2] = (unsigned char)ReadKernelMemoryViaSwap(InputBuffer, OutputBuffer, SwapBuffer, 0x10000);
                        break;
                    }

                    if (BytesRead)
                    {
                        *pCurrentOutput = 0;
                        if (LoopsWithoutProgress)
                            BytesRead = 0;
                        break;
                    }

                    if (InputByte0 == 1)
                        pCurrentOutput[2] = (unsigned char)ReadKernelMemoryViaSwap(InputBuffer, OutputBuffer, SwapBuffer, 0x10000);

                    *pCurrentOutput = OutputOffset;
                    WrittenSize = pCurrentOutput[3] + 16;
                    OutputOffset = WrittenSize;

                    if (OutputSize <= WrittenSize + 16)
                    {
                        *pCurrentOutput = 0;
                        break;
                    }

                    OutputSize -= WrittenSize;
                    pCurrentOutput = (unsigned int *)((char *)pCurrentOutput + WrittenSize);
                    CurrentPage++;
                    LoopsWithoutProgress++;
                }

                *(unsigned char *)((char *)KeGetCurrentThread() + PrevModeOffset) = SavedPrevMode;
                Result = (BytesRead == 0);
            }
            else
            {
                // 回退路径：使用 GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField102)
                AltReadFunc = GtRead(0x4189 | 0x100);
                if (AltReadFunc)
                {
                    pCurrentOutput = (unsigned int *)OutputBuffer;
                    LoopsWithoutProgress = 0;
                    OutputOffset = 0;

                    while (1)
                    {
                        BytesRead = (int)(((__int64 (__fastcall *)(__int64, unsigned int, unsigned int, unsigned int *, unsigned int, void *))AltReadFunc)(
                            TargetAddress, CurrentPage, EndFlag, pCurrentOutput, OutputSize, OutputParam));

                        if (EndFlag)
                            break;

                        if (ModeFlag == 1)
                        {
                            *pCurrentOutput = 0;
                            if (!BytesRead && InputByte0 == 1)
                                pCurrentOutput[2] = (unsigned char)ReadKernelMemoryViaSwapEx(InputBuffer, OutputBuffer, SwapBuffer, 0x10000);
                            break;
                        }

                        if (BytesRead)
                        {
                            *pCurrentOutput = 0;
                            if (LoopsWithoutProgress)
                                BytesRead = 0;
                            break;
                        }

                        if (InputByte0 == 1)
                            pCurrentOutput[2] = (unsigned char)ReadKernelMemoryViaSwapEx(InputBuffer, OutputBuffer, SwapBuffer, 0x10000);

                        *pCurrentOutput = OutputOffset;
                        WrittenSize = pCurrentOutput[3] + 16;
                        OutputOffset = WrittenSize;

                        if (OutputSize <= WrittenSize + 16)
                        {
                            *pCurrentOutput = 0;
                            break;
                        }

                        OutputSize -= WrittenSize;
                        pCurrentOutput = (unsigned int *)((char *)pCurrentOutput + WrittenSize);
                        CurrentPage++;
                        LoopsWithoutProgress++;
                    }

                    Result = (BytesRead == 0);
                }
            }
        }
    }

LABEL_READ_STRING_CLEANUP:
    if (SwapBuffer)
        ExFree(SwapBuffer);

    return Result;
}


// CopyUnicodeStringSafe — 安全复制 Unicode 字符串
// 对应原始驱动 sub_140087FA4
void CopyUnicodeStringSafe(const void **pSrcString, _WORD *pDstBuffer, int MaxLength)
{
    PVOID SrcBuffer;
    __int64 CopyLength;

    if (MaxLength)
    {
        *pDstBuffer = 0;
        if (CheckMemoryValid((void *)(ULONG_PTR)pSrcString) == 1 && CheckMemoryValid((char *)(ULONG_PTR)pSrcString + 15) == 1)
        {
            SrcBuffer = (PVOID)pSrcString[1];
            CopyLength = *(unsigned __int16 *)pSrcString >> 1;
            if ((unsigned int)CopyLength > (unsigned int)(MaxLength - 1))
                CopyLength = (unsigned int)(MaxLength - 1);
            if (SrcBuffer > MmSystemRangeStart
                && CheckMemoryValid(SrcBuffer) == 1
                && CheckMemoryValid((char *)pSrcString[1] + 2 * CopyLength - 2) == 1)
            {
                memmove(pDstBuffer, pSrcString[1], (unsigned int)(2 * CopyLength));
            }
            if ((_DWORD)CopyLength)
                pDstBuffer[CopyLength] = 0;
        }
    }
}


// GetDeviceObjectFromContext — 从上下文获取设备对象
// 从上下文结构偏移 16 处获取设备对象，若无效则从偏移 8 处获取驱动对象并返回其设备对象列表
// 对应原始驱动 sub_140047864
__int64 GetDeviceObjectFromContext(__int64 pContext)
{
    __int64 pDeviceObject;
    __int64 pResult;
    __int64 pDriverObject;

    pDeviceObject = *(_QWORD *)(pContext + 16);
    if (!pDeviceObject || (pResult = *(_QWORD *)(pDeviceObject + 8)) == 0)
    {
        pResult = *(_QWORD *)(pContext + 8);
        if ((*(_DWORD *)(pContext + 80) & 0x800) == 0)
        {
            pDriverObject = *(_QWORD *)(pResult + 56);
            if (pDriverObject)
                return *(_QWORD *)(pDriverObject + 8);
        }
    }
    return pResult;
}


// GetDiskDriverInfo — 获取磁盘驱动信息
// 从 GT 6914 的导出表中获取指定插槽的磁盘驱动函数指针，通过原子交换 16 字节数据返回当前驱动信息
// 对应原始驱动 sub_140049A9C
char GetDiskDriverInfo(char Slot, _OWORD *pBuffer, __int64 *pFuncTable)
{
    char Result;
    __int64 *pExportTable;
    __int64 pSlotEntry;

    Result = 0;
    *pFuncTable = 0;
    if ((unsigned int)GtRead(GtEprocessField135 | 0x100))
    {
        pExportTable = GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableBase | GtCallbackField52 | 0x1000));
        if (pExportTable)
        {
            if (Slot == 1)
                pSlotEntry = (__int64)(pExportTable + 90);
            else
                pSlotEntry = (__int64)(pExportTable + 84);
            if (*(_DWORD *)(pSlotEntry + 4) && *(_DWORD *)pSlotEntry == 1)
            {
                *pFuncTable = *(_QWORD *)(pSlotEntry + 8);
                return AtomicExchange16Bytes(pSlotEntry, pBuffer);
            }
        }
    }
    return Result;
}


// SetDiskDriverInfo — 设置磁盘驱动信息
// 从 GT 6914 的导出表中获取指定插槽，通过原子写入 16 字节恢复磁盘驱动信息缓冲区
// 对应原始驱动 sub_140049B28
char SetDiskDriverInfo(char Slot, char Flags, _OWORD *pBuffer)
{
    char Result;
    __int64 *pExportTable;
    __int64 pSlotEntry;

    Result = 0;
    if (Slot == 1)
    {
        if ((unsigned int)GtRead(GtEprocessField135 | 0x100))
        {
            pExportTable = GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableBase | GtCallbackField52 | 0x1000));
            if (pExportTable)
            {
                if (Flags == 1)
                    pSlotEntry = (__int64)(pExportTable + 90);
                else
                    pSlotEntry = (__int64)(pExportTable + 84);
                AtomicWrite16Bytes(pSlotEntry, pBuffer); return 1;
            }
        }
    }
    return Result;
}


// OpenDeviceTarget — 打开设备目标
// 对应原始驱动 sub_140047B10
char OpenDeviceTarget(__int64 DevicePath, __int64 IoctlBuffer, _QWORD *pDeviceHandle)
{
    char Result;
    void (__fastcall *InitObjectAttributes)(_BYTE *, __int64);
    unsigned int (__fastcall *OpenDevice)(_QWORD *, __int64, int *, _BYTE *, _DWORD, int);
    unsigned int (__fastcall *DeviceIoControl)(_QWORD, __int64, _QWORD, _QWORD, __int64, _QWORD);
    void (__fastcall *CloseHandle)(_QWORD);
    __int64 DeviceObjPtr;
    _QWORD *DeviceObject;
    _BYTE ObjectAttributesBuffer[16];
    _BYTE IoctlOutputBuffer[16];
    int IoStatusBlock;
    __int64 UnusedField;
    _BYTE *ObjAttrPtr;
    int OpenFlags;
    _OWORD ZeroStruct;

    Result = 0;
    InitObjectAttributes = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    OpenDevice = (unsigned int (__fastcall *)(_QWORD *, __int64, int *, _BYTE *, _DWORD, int))GtRead(GtTotalSize | GtObjectTypeField30 | GtDriverObject);
    DeviceIoControl = (unsigned int (__fastcall *)(_QWORD, __int64, _QWORD, _QWORD, __int64, _QWORD))GtRead(GtNtFsControlFileFunc);
    CloseHandle = (void (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);
    DeviceObjPtr = GtRead(GtZwCreateFileFunc);
    DeviceObject = (_QWORD *)DeviceObjPtr;
    if (InitObjectAttributes && OpenDevice && DeviceIoControl && CloseHandle && DeviceObjPtr)
    {
        InitObjectAttributes(ObjectAttributesBuffer, DevicePath);
        memset(&ZeroStruct, 0, sizeof(ZeroStruct));
        ObjAttrPtr = ObjectAttributesBuffer;
        IoStatusBlock = 48;
        UnusedField = 0;
        OpenFlags = 576;
        if (!OpenDevice(pDeviceHandle, 0x10000000, &IoStatusBlock, IoctlOutputBuffer, 0, 64))
        {
            if (DeviceIoControl(*pDeviceHandle, 0x80000000LL, *DeviceObject, 0, IoctlBuffer, 0))
                CloseHandle(*pDeviceHandle);
            else
                return 1;
        }
    }
    return Result;
}


// ReadModifyWriteDiskSector — 读取修改写入磁盘扇区
// 对应原始驱动 sub_14007CA18
char ReadModifyWriteDiskSector(int UseProcessDiskData, unsigned int SectorIndex)
{
    char Result;
    struct _DEVICE_OBJECT *pDeviceObject;
    struct _IRP *pIrp;
    unsigned int SectorSize;
    void *pBuffer;
    unsigned int Index;
    _BYTE *pByte;

    Result = 0;
    if (UseProcessDiskData) SectorIndex = 0;
    if (SectorIndex < 0x40)
    {
        pDeviceObject = (struct _DEVICE_OBJECT *)QueryObjectTypeDirectoryPath();
        if (pDeviceObject)
        {
            pIrp = (struct _IRP *)ExAlloc(NonPagedPool, 0x18u);
            if (pIrp)
            {
                if (SendDiskDeviceInternalIrp((__int64)pDeviceObject, pIrp))
                {
                    SectorSize = *(&pIrp->Flags + 1);
                    pBuffer = ExAlloc(NonPagedPool, SectorSize);
                    if (pBuffer)
                    {
                        memset(pBuffer, 0, SectorSize);
                        if (SectorIndex)
                        {
                            if (!(unsigned int)DispatchDiskIrpWithHookInit(pDeviceObject, 3, pBuffer, SectorIndex, 1, SectorSize))
                                goto CHECK_BUFFER;
                        }
                        else
                        {
                            if ((unsigned char)ProcessDiskSectorData((__int64)pDeviceObject, 0, (__int64)pBuffer, SectorSize) == 1)
                            {
CHECK_BUFFER:
                                Index = 0;
                                if (SectorSize)
                                {
                                    pByte = (_BYTE *)pBuffer;
                                    do
                                    {
                                        if (*pByte) break;
                                        ++Index; ++pByte;
                                    } while (Index < SectorSize);
                                    if (Index < SectorSize)
                                        Result = (unsigned int)DispatchDiskIrpWithHookInit(pDeviceObject, 4, pBuffer, 0, 1, SectorSize) == 0;
                                }
                            }
                        }
                        ExFree(pBuffer);
                    }
                }
                ExFree(pIrp);
            }
        }
    }
    return Result;
}


// WriteDiskSectorsWithMbr — 带 MBR 写入磁盘扇区
// 对应原始驱动 sub_14007C7A8
char WriteDiskSectorsWithMbr(int UseProcessDiskData, unsigned int SectorOffset)
{
    char Result;
    struct _DEVICE_OBJECT *pDeviceObject;
    unsigned int *pIrp;
    SIZE_T SectorSize;
    __int64 pBuffer;
    unsigned int Index;
    _BYTE *pByte;
    int PartitionIndex;
    int StartSector;

    Result = 0;
    pDeviceObject = (struct _DEVICE_OBJECT *)QueryObjectTypeDirectoryPath();
    if (pDeviceObject)
    {
        pIrp = (unsigned int *)ExAlloc(NonPagedPool, 0x18u);
        if (pIrp)
        {
            if (SendDiskDeviceInternalIrp((__int64)pDeviceObject, (struct _IRP *)pIrp))
            {
                SectorSize = pIrp[5];
                pBuffer = (__int64)ExAlloc(NonPagedPool, (ULONG)SectorSize);
                if (pBuffer)
                {
                    memset((void *)pBuffer, 0, (unsigned int)SectorSize);
                    if (!(unsigned int)DispatchDiskIrpWithHookInit(pDeviceObject, 3, (void *)pBuffer, 0, 1, (unsigned int)SectorSize))
                    {
                        Index = 0;
                        if ((_DWORD)SectorSize)
                        {
                            pByte = (_BYTE *)pBuffer;
                            do
                            {
                                if (*pByte) break;
                                ++Index; ++pByte;
                            } while (Index < (unsigned int)SectorSize);
                            if (Index < (unsigned int)SectorSize && CheckMbrBootablePartition((void *)pBuffer))
                            {
                                PartitionIndex = 0;
                                while (*(_BYTE *)(pBuffer + 446) != 0x80)
                                {
                                    if ((unsigned int)++PartitionIndex >= 4) goto LABEL_EXIT;
                                }
                                StartSector = *(_DWORD *)(pBuffer + 454);
                                if (StartSector)
                                {
                                    memset((void *)pBuffer, 0, SectorSize);
                                    if (UseProcessDiskData)
                                    {
                                        if ((unsigned char)ProcessDiskSectorData((__int64)pDeviceObject, (unsigned int)(SectorSize * StartSector), (__int64)pBuffer, (unsigned int)SectorSize) == 1)
                                            goto CHECK_READ;
                                    }
                                    else if (SectorOffset < 0x100)
                                    {
                                        if (!(unsigned int)DispatchDiskIrpWithHookInit(pDeviceObject, 3, (void *)pBuffer, StartSector + SectorOffset, 1, (unsigned int)SectorSize))
                                        {
CHECK_READ:
                                            Index = 0; pByte = (_BYTE *)pBuffer;
                                            do { if (*pByte) break; ++Index; ++pByte; } while (Index < (unsigned int)SectorSize);
                                            if (Index < (unsigned int)SectorSize)
                                                Result = (unsigned int)DispatchDiskIrpWithHookInit(pDeviceObject, 4, (void *)pBuffer, StartSector, 1, (unsigned int)SectorSize) == 0;
                                        }
                                    }
                                }
                            }
                        }
                    }
LABEL_EXIT:
                    ExFree((void *)pBuffer);
                }
            }
            ExFree(pIrp);
        }
    }
    return Result;
}


// ReadWin32kBaseDriverFile — 读取 win32k 基础驱动文件
// 对应原始驱动 sub_140051920
char ReadWin32kBaseDriverFile(__int64 *pBuffer, unsigned int *pBufferSize)
{
    char Result;
    size_t MaxCount;
    void *Src;
    int EncodedPath[20];

    EncodedPath[6] = 7929971; EncodedPath[16] = 7929971; Result = 0;
    EncodedPath[0] = 5439580; EncodedPath[1] = 7536761; EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061; EncodedPath[4] = 7274607; EncodedPath[5] = 6029428;
    EncodedPath[7] = 7602291; EncodedPath[8] = 7143525; EncodedPath[9] = 3276851;
    EncodedPath[10] = 7798876; EncodedPath[11] = 7209065; EncodedPath[12] = 3276851;
    EncodedPath[13] = 6422635; EncodedPath[14] = 7536737; EncodedPath[15] = 3014757;
    EncodedPath[17] = 115;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        if (ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)pBuffer, pBufferSize) == 1)
        {
            ValidateWin32kBaseDriverImage(*pBuffer, *pBufferSize);
            Result = 1;
        }
        ExFree(Src);
    }
    return Result;
}

// 对应原始驱动 0x14007D4E4（579 字节）
__int64 __fastcall ProcessDiskSectorData(
    __int64 ObjectHandle,
    __int64 arg2,
    __int64 arg3,
    unsigned int arg4)
{
    __int64 Result;
    __int64 (*QueryObjectNameFunc)(__int64, __int64, __int64, __int64 *);
    __int64 (*pIrpDispatchFunc)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64);
    __int64 (*pDiskIoFunc)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64);
    __int64 (*pCloseHandleFunc)(__int64, __int64, __int64);
    __int64 (*pCleanupFunc)(__int64, __int64, __int64);
    unsigned int RequiredSize;
    void *Buffer;
    unsigned int AllocSize;
    __int64 Handle;
    int Status;
    __int64 var_70;
    __int64 var_80;
    __int64 var_98;
    __int64 var_A0;

    QueryObjectNameFunc = (__int64 (*)(__int64, __int64, __int64, __int64 *))GtRead(GtQueryObjectNameFunc);
    pIrpDispatchFunc = (__int64 (*)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64))GtRead(0x4244);
    pDiskIoFunc = (__int64 (*)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64))GtRead(0x4328);
    pCloseHandleFunc = (__int64 (*)(__int64, __int64, __int64))GtRead(0x432B);
    pCleanupFunc = (__int64 (*)(__int64, __int64, __int64))GtRead(GtExFreePoolFunc);

    Result = 0;
    Buffer = NULL;

    if (!QueryObjectNameFunc || !pIrpDispatchFunc || !pDiskIoFunc || !pCloseHandleFunc || !pCleanupFunc)
        return Result;

    // 第一次调用获取所需缓冲区大小
    var_A0 = 0;
    Status = (int)QueryObjectNameFunc(ObjectHandle, 0, 0, &var_A0);
    if (Status != 0xC0000004)  // STATUS_INFO_LENGTH_MISMATCH
        return Result;

    RequiredSize = (unsigned int)var_A0;
    if (!RequiredSize)
        return Result;

    // 分配缓冲区
    AllocSize = RequiredSize + 0x100;
    Buffer = ExAlloc(0, AllocSize);
    if (!Buffer)
        return Result;

    // 第二次调用获取对象名称
    Status = (int)QueryObjectNameFunc(ObjectHandle, (__int64)Buffer, RequiredSize, &var_A0);
    if (Status != 0)
        goto Cleanup;

    // 验证缓冲区结构
    if (*(unsigned __int64 *)((PUCHAR)Buffer + 8) != (unsigned __int64)Buffer + 0x10)
        goto Cleanup;

    if ((unsigned int)(*(unsigned __int16 *)Buffer) + 0x10 >= AllocSize)
        goto Cleanup;

    // 构建 IRP 相关结构并调用
    {
        __int64 IrpCreateParams[4];

        // 第一个 IRP 创建尝试
        IrpCreateParams[0] = 0x30;          // Size
        IrpCreateParams[1] = 0;             //  flags
        IrpCreateParams[2] = (__int64)Buffer; // Buffer
        IrpCreateParams[3] = 0x240;         //  AllocationSize

        Status = (int)pIrpDispatchFunc(
            (__int64)&var_98,                // 输出 Handle
            (__int64)IrpCreateParams,        // 输入参数
            (__int64)&var_80,                // 输出状态
            0x20,                            // 结构大小
            1,                               // 选项1
            1,                               // 选项2
            0x80,                            // 选项3
            0);                              // 选项4

        if (Status < 0)
        {
            // 第二次尝试，使用不同的参数
            Status = (int)pIrpDispatchFunc(
                (__int64)&var_98,
                (__int64)IrpCreateParams,
                (__int64)&var_80,
                0x20,
                1,
                3,
                0x80,
                0x100001);
        }

        if (Status >= 0)
        {
            // 成功，执行磁盘 I/O 操作
            Handle = var_98;
            var_70 = arg2;

            Status = (int)pDiskIoFunc(
                Handle,
                0,
                0,
                (__int64)&var_70,
                arg4,
                arg3,
                (__int64)&var_80,
                0);

            if (Status == 0x103)  // STATUS_END_OF_FILE
            {
                pCloseHandleFunc(Handle, 0, 0);
                Status = (int)var_80;
            }

            // 检查结果
            if (Status == 0)
                Result = 1;

            // 清理
            pCleanupFunc(Handle, 0, 0);
        }
    }

Cleanup:
    if (Buffer)
        ExFree(Buffer);

    return Result;
}

// ReadKernelMemoryViaSwap -- 通过交换缓冲区读取内核内存
// 对应原始驱动 sub_140074D5C（地址 0x140074D5C，411 字节，114 条指令）
// 【逆向来源】人工阅读反汇编逐条重建 —— 与 ReadKernelMemoryViaSwapEx 同因（IDA 无法
//   分析该函数，Hex-Rays 报 "function frame is wrong"，无伪代码可用）
// 【验证依据】调用者同为 CmdReadProcessMemoryStr(0x140074418)，其可反编译的伪代码给出
//   ReadKernelMemoryViaSwap(v46, v18, v8, v35)，实参 4 个与本实现签名一致；
//   与 Ex 版逐指令差分比对，确认仅三处不同（见下）
// 【存疑/注意】原函数名与实际行为不符（0x20019 = KEY_READ，实际读注册表键信息）
// 【与 Ex 版的差异（逐指令差分结论）】
//   1) 三个全局表索引不同：0x16E / 0x4334(ExFreePool) / 0x172
//   2) 打开对象之前额外调用 SwapKernelMemoryPointer(&SavedValue) 取得"交换槽"指针
//   3) 打开之后**无条件**执行 *pSwapSlot = SavedValue，随后才判断打开状态
//       （此顺序由汇编确认：写回在状态判断之前，容易写反）
// 【其余逻辑】与 Ex 版完全一致：长度检查 → 拼接"基串 + '\' + 子串" →
//   UNICODE_STRING + OBJECT_ATTRIBUTES → 打开(0x20019) → 查询(类别 2) →
//   Result = (*(DWORD*)(SwapBuffer + 0x14) != 0) → 释放句柄
// 对应原始驱动 0x140074D5C（411 字节）
__int64 ReadKernelMemoryViaSwap(void *InputBuffer, void *OutputBuffer, void *SwapBuffer, unsigned int BufferSize)
{
    NTSTATUS(__fastcall *OpenObjectFunc)(HANDLE *, ULONG, POBJECT_ATTRIBUTES);
    void(__fastcall *ReleaseFunc)(HANDLE);
    NTSTATUS(__fastcall *QueryObjectFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    __int64 *pSwapSlot;
    __int64 SavedValue;
    NTSTATUS Status;
    char Result;
    unsigned int BaseLength;
    unsigned int SubLength;
    unsigned int TotalLength;
    HANDLE ObjectHandle;
    ULONG ReturnLength;
    UNICODE_STRING ObjectPath;
    struct _OBJECT_ATTRIBUTES ObjectAttributes;

    Result = 0;
    ObjectHandle = NULL;
    SavedValue = 0;
    BaseLength = *(unsigned int *)((char *)InputBuffer + 4);
    SubLength = *(unsigned int *)((char *)OutputBuffer + 0xC);

    OpenObjectFunc = (NTSTATUS(__fastcall *)(HANDLE *, ULONG, POBJECT_ATTRIBUTES))GtRead((GLOBAL_TABLE_INDEX)0x16E);
    ReleaseFunc = (void(__fastcall *)(HANDLE))GtRead(GtExFreePoolFunc);
    QueryObjectFunc = (NTSTATUS(__fastcall *)(HANDLE, ULONG, PVOID, ULONG, PULONG))GtRead((GLOBAL_TABLE_INDEX)0x172);
    if (!OpenObjectFunc || !ReleaseFunc || !QueryObjectFunc)
        return Result;

    TotalLength = BaseLength + SubLength + 2;
    if (TotalLength >= BufferSize)
        return Result;

    memmove(SwapBuffer, *(const void **)((char *)InputBuffer + 8), BaseLength);
    *(WORD *)((char *)SwapBuffer + BaseLength - 2) = 0x5C;
    memmove((char *)SwapBuffer + BaseLength, *(const void **)((char *)OutputBuffer + 0x10), SubLength);
    *(WORD *)((char *)SwapBuffer + BaseLength + SubLength) = 0;

    ObjectPath.Length = (USHORT)(TotalLength - 2);
    ObjectPath.MaximumLength = (USHORT)TotalLength;
    ObjectPath.Buffer = (PWSTR)SwapBuffer;

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = NULL;
    ObjectAttributes.ObjectName = &ObjectPath;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.SecurityDescriptor = NULL;
    ObjectAttributes.SecurityQualityOfService = NULL;

    pSwapSlot = SwapKernelMemoryPointer(&SavedValue);
    Status = OpenObjectFunc(&ObjectHandle, 0x20019, &ObjectAttributes);
    if (pSwapSlot)
        *pSwapSlot = SavedValue;
    if (Status < 0)
        return Result;

    ReturnLength = 0;
    if (QueryObjectFunc(ObjectHandle, 2, SwapBuffer, BufferSize, &ReturnLength) >= 0)
    {
        if (*(unsigned int *)((char *)SwapBuffer + 0x14) > 0)
            Result = 1;
    }
    ReleaseFunc(ObjectHandle);
    return Result;
}

// ReadKernelMemoryViaSwapEx -- 通过交换缓冲区读取内核内存（扩展版）
// 对应原始驱动 sub_140075874（地址 0x140075874，385 字节，106 条指令）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"；已试 reanalyze_function 与 删除+auto_make_proc 重建，
//   均无效，因此没有伪代码可用，逻辑全部由反汇编数据流还原）
// 【验证依据】1) 调用点 CmdReadProcessMemoryStr(0x140074418) 可反编译，其伪代码给出
//   实参为 4 个：ReadKernelMemoryViaSwapEx(Address, v5, v8, v35)，与本实现签名一致；
//   2) 访问掩码 0x20019 = KEY_READ、查询类别 2，据此判定语义为"打开并查询注册表键"
// 【存疑/注意】原函数名与实际行为不符（实际读的是注册表键信息，非内核内存）；
//   三个全局表槽位(0x41F3/0x4334/0x4205)在头文件中的别名不可信（该区域是"先存哈希、
//   运行时被解析地址覆盖"的槽位），故按调用形态而非别名理解
// 【逻辑】
//   1) 取全局表已解析的三个例程 0x41F3 / 0x4334(ExFreePool) / 0x4205，任一为空即返回 0
//   2) 长度检查：InputBuffer->len(+4) + OutputBuffer->len(+0xC) + 2 >= BufferSize 则返回 0
//   3) 在 SwapBuffer 中拼路径：基串(+8) → 末两字节改写为 '\' → 追加子串(+0x10) → 补 0
//   4) 构造 UNICODE_STRING{Length=总长-2, MaximumLength=总长, Buffer=SwapBuffer}
//      与 OBJECT_ATTRIBUTES{Length=48, Attributes=0x240, ObjectName=上述串}
//   5) 打开(&句柄, 0x20019, &OA)
//   6) 查询(句柄, 2, SwapBuffer, BufferSize, &实际长度) —— 结果覆盖写入同一缓冲区
//   7) Result = (*(DWORD*)(SwapBuffer + 0x14) != 0)；最后释放句柄
// 对应原始驱动 0x140075874（385 字节）
__int64 ReadKernelMemoryViaSwapEx(void *InputBuffer, void *OutputBuffer, void *SwapBuffer, unsigned int BufferSize)
{
    NTSTATUS(__fastcall *OpenObjectFunc)(HANDLE *, ULONG, POBJECT_ATTRIBUTES);
    void(__fastcall *ReleaseFunc)(HANDLE);
    NTSTATUS(__fastcall *QueryObjectFunc)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    char Result;
    unsigned int BaseLength;
    unsigned int SubLength;
    unsigned int TotalLength;
    HANDLE ObjectHandle;
    ULONG ReturnLength;
    UNICODE_STRING ObjectPath;
    struct _OBJECT_ATTRIBUTES ObjectAttributes;

    Result = 0;
    ObjectHandle = NULL;
    BaseLength = *(unsigned int *)((char *)InputBuffer + 4);
    SubLength = *(unsigned int *)((char *)OutputBuffer + 0xC);

    OpenObjectFunc = (NTSTATUS(__fastcall *)(HANDLE *, ULONG, POBJECT_ATTRIBUTES))GtRead((GLOBAL_TABLE_INDEX)0x41F3);
    ReleaseFunc = (void(__fastcall *)(HANDLE))GtRead(GtExFreePoolFunc);
    QueryObjectFunc = (NTSTATUS(__fastcall *)(HANDLE, ULONG, PVOID, ULONG, PULONG))GtRead((GLOBAL_TABLE_INDEX)0x4205);
    if (!OpenObjectFunc || !ReleaseFunc || !QueryObjectFunc)
        return Result;

    TotalLength = BaseLength + SubLength + 2;
    if (TotalLength >= BufferSize)
        return Result;

    memmove(SwapBuffer, *(const void **)((char *)InputBuffer + 8), BaseLength);
    *(WORD *)((char *)SwapBuffer + BaseLength - 2) = 0x5C;
    memmove((char *)SwapBuffer + BaseLength, *(const void **)((char *)OutputBuffer + 0x10), SubLength);
    *(WORD *)((char *)SwapBuffer + BaseLength + SubLength) = 0;

    ObjectPath.Length = (USHORT)(TotalLength - 2);
    ObjectPath.MaximumLength = (USHORT)TotalLength;
    ObjectPath.Buffer = (PWSTR)SwapBuffer;

    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = NULL;
    ObjectAttributes.ObjectName = &ObjectPath;
    ObjectAttributes.Attributes = 576;
    ObjectAttributes.SecurityDescriptor = NULL;
    ObjectAttributes.SecurityQualityOfService = NULL;

    if (OpenObjectFunc(&ObjectHandle, 0x20019, &ObjectAttributes) >= 0)
    {
        ReturnLength = 0;
        if (QueryObjectFunc(ObjectHandle, 2, SwapBuffer, BufferSize, &ReturnLength) >= 0)
        {
            if (*(unsigned int *)((char *)SwapBuffer + 0x14) > 0)
                Result = 1;
        }
        ReleaseFunc(ObjectHandle);
    }
    return Result;
}
// 对应原始驱动 0x14007A5F0（5 字节）
void *j_GetCurrentFiber(void)
{
    return GetCurrentFiber();
}
