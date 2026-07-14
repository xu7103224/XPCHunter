// Utility.c — 通用工具函数集合
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"

// StringLength — 获取ANSI字符串长度
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
__int64 MemoryCompare(__int64 Buf1, char *Buf2, unsigned int Size)
{
    __int64 Result = 0;
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