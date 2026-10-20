// ============================================================================
// XPCHunterUM — 用户态客户端与内核驱动的通信协议实现
//
// 全部依据原始 PCHunter64.exe 的 sub_14004DD40（通信主函数）与原始驱动
// DispatchDeviceControl（0x1400823EC）反汇编，两侧交叉验证：
//
//   用户态 sub_14004DD40 派生的  ioctl=0x05E00158、keybyte=0xCF
//   驱动侧实机 GT[0x1E0]=0x05E00158、GT[0x1E1]=0xCF
//   —— 完全一致，证明两侧算法理解正确。
//
// 请求结构（0x30 字节）：
//     0x00  DWORD  Magic         = 0x20240810
//     0x04  DWORD  Command       [0x20, 0x13A]
//     0x08  QWORD  OutputBuffer
//     0x10  QWORD  ContextPointer
//     0x18  QWORD  ExtraPointer
//     0x20  DWORD  OutputSize
//     0x24  DWORD  ContextSize
//     0x28  DWORD  Checksum      = MD5(明文前 0x28 字节)[0..3]
// ============================================================================

#include "XPCHunterUM.h"
#include <stdio.h>

/* ---------------------------------------------------------------------------
 * MD5（RFC 1321），与内核 InitMd5Context/Md5Update/Md5Final 等价。
 * 内核对**明文**前 0x28 字节求摘要（0x140082491..4B1）。
 * ------------------------------------------------------------------------- */

typedef struct {
    ULONG State[4];
    ULONG Count[2];
    UCHAR Buffer[64];
} XPCH_MD5_CTX;

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))
#define MD5STEP(f, w, x, y, z, in, s) \
    (w += f(x, y, z) + in, w = (w << s | w >> (32 - s)) + x)

static void XpchMd5Transform(ULONG State[4], const UCHAR Block[64])
{
    ULONG a = State[0], b = State[1], c = State[2], d = State[3];
    ULONG in[16];
    int i;

    for (i = 0; i < 16; i++)
        in[i] = (ULONG)Block[i * 4] | ((ULONG)Block[i * 4 + 1] << 8)
              | ((ULONG)Block[i * 4 + 2] << 16) | ((ULONG)Block[i * 4 + 3] << 24);

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    State[0] += a; State[1] += b; State[2] += c; State[3] += d;
}

static void XpchMd5Init(XPCH_MD5_CTX *Ctx)
{
    Ctx->Count[0] = Ctx->Count[1] = 0;
    Ctx->State[0] = 0x67452301;
    Ctx->State[1] = 0xefcdab89;
    Ctx->State[2] = 0x98badcfe;
    Ctx->State[3] = 0x10325476;
}

static void XpchMd5Update(XPCH_MD5_CTX *Ctx, const UCHAR *Input, ULONG Len)
{
    ULONG i, Index, PartLen;
    Index = (Ctx->Count[0] >> 3) & 0x3F;
    if ((Ctx->Count[0] += Len << 3) < (Len << 3))
        Ctx->Count[1]++;
    Ctx->Count[1] += Len >> 29;
    PartLen = 64 - Index;
    if (Len >= PartLen) {
        memcpy(&Ctx->Buffer[Index], Input, PartLen);
        XpchMd5Transform(Ctx->State, Ctx->Buffer);
        for (i = PartLen; i + 63 < Len; i += 64)
            XpchMd5Transform(Ctx->State, &Input[i]);
        Index = 0;
    } else {
        i = 0;
    }
    memcpy(&Ctx->Buffer[Index], &Input[i], Len - i);
}

static void XpchMd5Final(XPCH_MD5_CTX *Ctx, UCHAR Digest[16])
{
    UCHAR Bits[8];
    ULONG i, Index, PadLen;
    static const UCHAR PADDING[64] = { 0x80 };
    for (i = 0; i < 4; i++) {
        Bits[i]     = (UCHAR)(Ctx->Count[0] >> (i * 8));
        Bits[i + 4] = (UCHAR)(Ctx->Count[1] >> (i * 8));
    }
    Index = (Ctx->Count[0] >> 3) & 0x3F;
    PadLen = (Index < 56) ? (56 - Index) : (120 - Index);
    XpchMd5Update(Ctx, PADDING, PadLen);
    XpchMd5Update(Ctx, Bits, 8);
    for (i = 0; i < 4; i++) {
        Digest[i * 4]     = (UCHAR)Ctx->State[i];
        Digest[i * 4 + 1] = (UCHAR)(Ctx->State[i] >> 8);
        Digest[i * 4 + 2] = (UCHAR)(Ctx->State[i] >> 16);
        Digest[i * 4 + 3] = (UCHAR)(Ctx->State[i] >> 24);
    }
}

/* ---------------------------------------------------------------------------
 * 密钥与 IOCTL 码派生
 *
 * 严格复刻 sub_14004DD40 的 0x14004DDCF..0x14004DE46：
 *
 *   Destination = L"\\\\.\\" + Name            （宽字符缓冲）
 *   n = wcslen(Destination)
 *
 *   /* 第 1 段：edi 从 0x20 起，取 Destination+8 字节起的 (n-4) 个 WORD *\/
 *   edi = 0x20;
 *   for (i = 0; i < n-4; i++) {
 *       w = *(WORD*)(DestBytes + 8 + i*2);
 *       edi = w ^ (w + edi);
 *   }
 *
 *   /* IOCTL 码 *\/
 *   ioctl = 4 * (DestBytes[8] | (edi << 14));      // DestBytes[8] = Name[0] 低字节
 *
 *   /* 第 2 段：keyByte 从 Destination+8 字节起走 2n-8 字节 *\/
 *   key = 0x20;
 *   for each byte c in DestBytes[8 .. 2n]:
 *       c ? (key ^= c) : (key = (key>>4) + 16*key);
 *
 * 实机校验：Name = L"View++ByLinxer" →
 *   ioctl = 0x05E00158（= 驱动 GT[0x1E0]）
 *   key   = 0xCF      （= 驱动 GT[0x1E1]）
 * ------------------------------------------------------------------------- */

/* 从设备名（不含 "\\.\"）派生 ioctl 与 keyByte */
BOOL XpchDeriveParams(const WCHAR *Name, PULONG IoControlCode, PUCHAR KeyByte)
{
    WCHAR Dest[64];
    UCHAR *Bytes;
    ULONG n, i, edi, first;
    UCHAR key;

    if (!Name || !IoControlCode || !KeyByte)
        return FALSE;

    /* 构造 "\\.\" + Name —— 前缀是 4 个字符：'\','\','.','\' */
    {
        const WCHAR *p = L"\\\\.\\";
        ULONG k = 0;
        while (p[k] && k < 4) { Dest[k] = p[k]; k++; }
        for (i = 0; Name[i] && k < 63; i++)
            Dest[k++] = Name[i];
        Dest[k] = 0;
        n = k;
    }
    if (n <= 4)
        return FALSE;

    Bytes = (UCHAR *)Dest;

    /* 第 1 段 */
    edi = 0x20;
    for (i = 0; i < n - 4; i++) {
        ULONG w = (ULONG)Bytes[8 + i * 2] | ((ULONG)Bytes[9 + i * 2] << 8);
        edi = (w ^ ((w + edi) & 0xFFFFFFFF)) & 0xFFFFFFFF;
    }
    first = Bytes[8];
    *IoControlCode = (4 * (first | ((edi << 14) & 0xFFFFFFFF))) & 0xFFFFFFFF;

    /* 第 2 段 */
    key = 0x20;
    for (i = 8; i < 2 * n; i++) {
        UCHAR c = Bytes[i];
        if (c)
            key = (UCHAR)(key ^ c);
        else
            key = (UCHAR)((key >> 4) + 16 * key);
    }
    *KeyByte = key;

    return TRUE;
}

/* 自反：b' = ~(b ^ key) */
void XpchCryptBuffer(PUCHAR Buffer, ULONG Size, UCHAR KeyByte)
{
    ULONG i;
    for (i = 0; i < Size; i++)
        Buffer[i] = (UCHAR)~(Buffer[i] ^ KeyByte);
}

BOOL XpchOpen(PXPCH_CLIENT Client)
{
    if (!Client)
        return FALSE;

    ZeroMemory(Client, sizeof(*Client));
    Client->Device = CreateFileW(XPCH_DEVICE_NAME,
                                 GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL,
                                 NULL);
    if (Client->Device == INVALID_HANDLE_VALUE) {
        Client->Device = NULL;
        return FALSE;
    }

    if (!XpchDeriveParams(XPCH_DEVICE_SUFFIX, &Client->IoControlCode, &Client->KeyByte)) {
        CloseHandle(Client->Device);
        Client->Device = NULL;
        return FALSE;
    }
    Client->Opened = TRUE;
    return TRUE;
}

void XpchClose(PXPCH_CLIENT Client)
{
    if (Client && Client->Device) {
        CloseHandle(Client->Device);
        Client->Device = NULL;
        Client->Opened = FALSE;
    }
}

BOOL XpchInvoke(PXPCH_CLIENT Client,
                ULONG Command,
                PVOID Output, ULONG OutputSize,
                PVOID Context, ULONG ContextSize,
                PVOID Extra)
{
    XPCH_REQUEST Req;
    UCHAR Digest[16];
    XPCH_MD5_CTX Md5;
    DWORD Returned = 0;
    BOOL Status;

    if (!Client || !Client->Opened || !Client->Device)
        return FALSE;
    if (Command < XPCH_CMD_MIN || Command > XPCH_CMD_MAX) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ZeroMemory(&Req, sizeof(Req));
    Req.Magic          = XPCH_MAGIC;
    Req.Command        = Command;
    Req.OutputBuffer   = (ULONG64)(ULONG_PTR)Output;
    Req.ContextPointer = (ULONG64)(ULONG_PTR)Context;
    Req.ExtraPointer   = (ULONG64)(ULONG_PTR)Extra;
    Req.OutputSize     = OutputSize;
    Req.ContextSize    = ContextSize;

    /* 校和：对明文前 0x28 字节求 MD5，取前 4 字节 */
    XpchMd5Init(&Md5);
    XpchMd5Update(&Md5, (const UCHAR *)&Req, XPCH_CHECKSUM_OFFSET);
    XpchMd5Final(&Md5, Digest);
    Req.Checksum = (ULONG)Digest[0]
                 | ((ULONG)Digest[1] << 8)
                 | ((ULONG)Digest[2] << 16)
                 | ((ULONG)Digest[3] << 24);

    /* 整体加密（内核收到后会再解一次） */
    XpchCryptBuffer((PUCHAR)&Req, XPCH_REQUEST_SIZE, Client->KeyByte);

    /*
     * 原始用户态用同一块 0x30 缓冲做输入与输出（lpInBuffer 既作 InBuffer
     * 又作 OutBuffer），这里保持一致。
     */
    Status = DeviceIoControl(Client->Device,
                             Client->IoControlCode,
                             &Req, XPCH_REQUEST_SIZE,
                             &Req, XPCH_REQUEST_SIZE,
                             &Returned, NULL);
    if (!Status)
        return FALSE;
    return Returned != 0;
}

BOOL XpchHandshake(PXPCH_CLIENT Client)
{
    ULONG Build = 0;

    (void)XpchInvoke(Client, XPCH_CMD_QUERY_PROCESS_INFO, NULL, 0, NULL, 0, NULL);

    if (!XpchInvoke(Client, XPCH_CMD_RESET_PROCESS_CONTEXT, NULL, 0, NULL, 0, NULL))
        return FALSE;

    if (XpchInvoke(Client, XPCH_CMD_GET_MODULE_COUNT, &Build, sizeof(Build), NULL, 0, NULL))
        return Build != 0;

    return FALSE;
}