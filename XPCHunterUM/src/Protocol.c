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
    /* 【2026-10-23】0x8771f683（不是标准的 0x8771f681）—— 原版驱动的
       常量表里这一项差 2，是原版自身的笔误。必须照抄，否则两侧协议不通。
       定位依据见 XPCHunterDrv/src/framework/Crypto.c 的 Md5_K 注释。 */
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f683, 11);
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

/* ---------------------------------------------------------------------------
 * AES-128-ECB 加密（构造 0x22 的许可包用）
 *
 * 驱动机 Crypto.c 的 DecryptAesHexString(0x140002F4C) 解密流程：
 *   1) 输入 0x100 字节十六进制字符串 → 解成 0x80 字节二进制
 *   2) 用密钥 "ShouJiErShiSiShi"(16 字节) 做 AES-128 解密
 *   3) 对明文前 0x64 字节做 MD5，与明文 [0x64..0x74) 比对
 *   4) 明文 [0x50..0x58) 与 [0x58..0x60) 是允许的系统时间窗（FILETIME 风格）
 *   5) 全部通过才返回 0（即"合法包"）
 * 所以用户态必须做一次等价的 AES-128 **加密** 来生成这个包。
 *
 * 本实现的正确性用 FIPS-197 附录 B 向量自测：
 *   key=2b7e151628aed2a6abf7158809cf4f3c
 *   pt =3243f6a8885a308d313198a2e0370734
 *   ct =3925841d02dc09fbdc118597196a0b32
 * ------------------------------------------------------------------------- */

static const UCHAR g_AesSbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static UCHAR AesXtime(UCHAR a)
{
    return (UCHAR)((a << 1) ^ ((a & 0x80) ? 0x1B : 0));
}

/* 密钥扩展：把 16 字节密钥展开成 11 组轮密钥（每组 16 字节） */
static void Aes128ExpandKey(const UCHAR Key[16], UCHAR RoundKeys[176])
{
    static const UCHAR Rcon[10] = {1,2,4,8,0x10,0x20,0x40,0x80,0x1B,0x36};
    ULONG i;
    UCHAR Tmp[4];

    CopyMemory(RoundKeys, Key, 16);
    for (i = 16; i < 176; i += 4) {
        CopyMemory(Tmp, &RoundKeys[i - 4], 4);
        if ((i % 16) == 0) {
            /* RotWord + SubWord + Rcon */
            UCHAR t = Tmp[0];
            Tmp[0] = (UCHAR)(g_AesSbox[Tmp[1]] ^ Rcon[i / 16 - 1]);
            Tmp[1] = g_AesSbox[Tmp[2]];
            Tmp[2] = g_AesSbox[Tmp[3]];
            Tmp[3] = g_AesSbox[t];
        }
        RoundKeys[i + 0] = (UCHAR)(RoundKeys[i - 16 + 0] ^ Tmp[0]);
        RoundKeys[i + 1] = (UCHAR)(RoundKeys[i - 16 + 1] ^ Tmp[1]);
        RoundKeys[i + 2] = (UCHAR)(RoundKeys[i - 16 + 2] ^ Tmp[2]);
        RoundKeys[i + 3] = (UCHAR)(RoundKeys[i - 16 + 3] ^ Tmp[3]);
    }
}

/* 加密一个 16 字节块（状态按列主序：s[c*4+r]） */
void XpchAes128EncryptBlock(const UCHAR Key[16], const UCHAR In[16], UCHAR Out[16])
{
    UCHAR RK[176];
    UCHAR S[16];
    UCHAR T[16];
    ULONG Round, c, r, k;

    Aes128ExpandKey(Key, RK);
    for (k = 0; k < 16; k++)
        S[k] = (UCHAR)(In[k] ^ RK[k]);

    for (Round = 1; Round <= 10; Round++) {
        /* SubBytes */
        for (k = 0; k < 16; k++)
            S[k] = g_AesSbox[S[k]];

        /* ShiftRows：第 r 行左移 r 列 */
        for (c = 0; c < 4; c++)
            for (r = 0; r < 4; r++)
                T[c * 4 + r] = S[((c + r) & 3) * 4 + r];

        /* MixColumns（最后一轮不做） */
        if (Round != 10) {
            for (c = 0; c < 4; c++) {
                UCHAR a0 = T[c * 4 + 0], a1 = T[c * 4 + 1];
                UCHAR a2 = T[c * 4 + 2], a3 = T[c * 4 + 3];
                S[c * 4 + 0] = (UCHAR)(AesXtime(a0) ^ (AesXtime(a1) ^ a1) ^ a2 ^ a3);
                S[c * 4 + 1] = (UCHAR)(a0 ^ AesXtime(a1) ^ (AesXtime(a2) ^ a2) ^ a3);
                S[c * 4 + 2] = (UCHAR)(a0 ^ a1 ^ AesXtime(a2) ^ (AesXtime(a3) ^ a3));
                S[c * 4 + 3] = (UCHAR)((AesXtime(a0) ^ a0) ^ a1 ^ a2 ^ AesXtime(a3));
            }
        } else {
            for (k = 0; k < 16; k++)
                S[k] = T[k];
        }

        /* AddRoundKey */
        for (k = 0; k < 16; k++)
            S[k] = (UCHAR)(S[k] ^ RK[Round * 16 + k]);
    }

    CopyMemory(Out, S, 16);
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
                PVOID In, ULONG InSize,
                PVOID Out, ULONG OutSize,
                PUCHAR Result)
{
    XPCH_REQUEST Req;
    UCHAR Digest[16];
    XPCH_MD5_CTX Md5;
    DWORD Returned = 0;
    BOOL Status;
    BYTE ResultByte = 0;
    UCHAR Stored = 0;

    if (!Client || !Client->Opened || !Client->Device)
        return FALSE;
    if (Command < XPCH_CMD_MIN || Command > XPCH_CMD_MAX) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (Result)
        *Result = 0;

    ZeroMemory(&Req, sizeof(Req));
    Req.Magic         = XPCH_MAGIC;
    Req.Command       = Command;
    Req.ResultBytePtr = (ULONG64)(ULONG_PTR)&ResultByte;
    Req.InPtr         = (ULONG64)(ULONG_PTR)In;
    Req.OutPtr        = (ULONG64)(ULONG_PTR)Out;
    Req.InSize        = InSize;
    Req.OutSize       = OutSize;

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
     * 入参长度必须是 0x30，ioctl 必须是设备名派生的值 —— 内核分别用
     * IO_STACK_LOCATION 的 +0x10 / +0x18 比对（0x140082439 / 0x14008245B）。
     * 原始用户态也用同一块 0x30 缓冲作输入与输出，这里保持一致。
     */
    Status = DeviceIoControl(Client->Device,
                             Client->IoControlCode,
                             &Req, XPCH_REQUEST_SIZE,
                             &Req, XPCH_REQUEST_SIZE,
                             &Returned, NULL);
    if (!Status)
        return FALSE;

    /*
     * 驱动**从不设置** Irp->IoStatus.Information（0x140082603 只有
     * `and dword ptr [r14],0`，r14 = &IoStatus.Status），所以 lpBytesReturned
     * 恒为 0，不能用它判断。真正的结果码是驱动写回 ResultBytePtr 的那 1 字节：
     *   1 = 处理器执行且返回成功
     *   0 = 请求在任一道关卡被拒（ioctl / magic / MD5 / 范围 / 就绪 / 权限 / 锁）
     * 注意它写在独立的单字节变量里，不覆盖请求头（驱动用同一块 SystemBuffer
     * 收发，所以 OutPtr 绝不能指向 Req 自身）。
     */
    UNREFERENCED_PARAMETER(Returned);
    Stored = ResultByte;
    if (Result)
        *Result = Stored;
    return Stored != 0;
}

/* 构造 0x22 用的许可包（0x100 字节十六进制字符串，解出 0x80 字节）。
 *
 * 明文布局（与驱动 DecryptAesHexString 的校验一一对应）：
 *   [0x00..0x50)  任意数据（驱动不检查）
 *   [0x50..0x58)  时间窗下界（QWORD，小端）
 *   [0x58..0x60)  时间窗上界（QWORD，小端）
 *   [0x64..0x74)  明文 [0x00..0x64) 的 MD5
 *   [0x74..0x80)  任意填充
 * 明文整体再做 AES-128-ECB 加密 → 0x80 字节密文 → 转成 0x100 字节 HEX。
 *
 * 时间基准：驱动读 SharedUserData+0x14（KUSER_SHARED_DATA.SystemTime，
 * 即当前系统时间，FILETIME 单位）。用户态 GetSystemTimeAsFileTime 等价。
 * 这里给 [now-1 天, now+1 天] 的宽窗口。 */
BOOL XpchBuildLicensePacket(UCHAR OutHex[0x100])
{
    /* 【2026-10-22 修正】密钥必须与驱动 Crypto.c 的 DecryptAesHexString 完全一致。
       驱动侧是 4 个 DWORD：0x756F6853 "Shou" / 0x7245694A "JiEr" /
       0x53696853 "ShiS" / 0x69685369 "iShi"，
       拼起来正是 "ShouJiErShiSiShi"（16 字节，无 NUL）。
       此前误写成 "ShouJiErShiShi"(14 字节 + 2 个 NUL)，导致 AES 解密全部失败。 */
    static const UCHAR Key[16] = {
        'S','h','o','u','J','i','E','r','S','h','i','S','i','S','h','i'
    };
    UCHAR Plain[0x80];
    UCHAR Cipher[0x80];
    XPCH_MD5_CTX Md5;
    UCHAR Digest[16];
    ULONG i;
    ULONG64 Now, Lo, Hi;
    FILETIME Ft;

    if (!OutHex)
        return FALSE;

    ZeroMemory(Plain, sizeof(Plain));

    /* 时间窗：驱动比较的是 SharedUserData+0x14，与 GetSystemTimeAsFileTime
       同源（都是 100ns 单位）。留一天余量吸收时钟抖动。 */
    GetSystemTimeAsFileTime(&Ft);
    Now = ((ULONG64)Ft.dwHighDateTime << 32) | Ft.dwLowDateTime;
    Lo = (Now > (ULONG64)864000000000LL) ? Now - (ULONG64)864000000000LL : 1;
    Hi = Now + (ULONG64)864000000000LL;

    CopyMemory(&Plain[0x50], &Lo, 8);
    CopyMemory(&Plain[0x58], &Hi, 8);

    /* 前 0x64 字节的 MD5 放在 0x64 */
    XpchMd5Init(&Md5);
    XpchMd5Update(&Md5, Plain, 0x64);
    XpchMd5Final(&Md5, Digest);
    CopyMemory(&Plain[0x64], Digest, 16);

    /* AES-128-ECB 加密 0x80 字节（8 个块） */
    for (i = 0; i < sizeof(Plain); i += 16)
        XpchAes128EncryptBlock(Key, Plain + i, Cipher + i);

    /* 转成大写十六进制字符串 */
    {
        static const char HexDigits[] = "0123456789ABCDEF";
        for (i = 0; i < sizeof(Cipher); i++) {
            OutHex[i * 2]     = (UCHAR)HexDigits[Cipher[i] >> 4];
            OutHex[i * 2 + 1] = (UCHAR)HexDigits[Cipher[i] & 0x0F];
        }
    }
    return TRUE;
}

/* Handshake.
 *
 * 0x22 (CmdQueryProcessInfo) 是 GT[0x304]（驱动就绪标志）为 0 时唯一
 * 被放行的命令（分派器 0x140082532 的守卫）。它调用 CheckSsdtHookIntegrity，
 * 而后者是全驱动唯一把 GT[0x304] 置 1 的地方（0x1400051C4），所以必须先发它。
 *
 * 【2026-10-22 已确证的事实】0x22 有三条路径，副作用各不相同：
 *
 *   路径 A  InSize <= 0xA
 *       CmdQueryProcessInfo -> AllocProcessInfoBuffer() + CheckSsdtHookIntegrity
 *       AllocProcessInfoBuffer(0x1400813F0) 会执行
 *           memset(GtAlloc(GtCommandHandlerBase) + 198*8, 0, 0xD8)
 *       把命令表的槽 198..224（命令 0xE6..0x100）清零，另清 273..276。
 *       GT[0x1E0]（ioctl 码）不变。
 *       【现状】我方一直走这条，代价是 0xEF..0xF8、0x131 的处理器被抹掉。
 *
 *   路径 B  InSize ∈ (0xA, 0x12C] 且包不合法
 *       QuerySsdHookByProcessInfo: GT[0x1E0] -= 1
 *       DecryptAesHexString 失败: GT[0x1E0] += 1
 *       CheckSsdtHookIntegrity(Dst=内核栈, ...): GT[0x1E0] += 2
 *       净 +2 —— ioctl 码漂移，之后所有命令都被分派器拒绝。
 *       **这条路不能走。**
 *
 *   路径 C  InSize == 0x100 且 AES 包完全合法（MD5 + 时间窗都对）
 *       GT[0x1E0] 净变化 0，GT[0x304] 置 1，命令表不受影响。
 *       这是原版前端走的路径。
 *
 * 实测对照（kd 读原版驱动运行时的 g_GlobalTable，基址 fffff805`31500000）：
 *     槽 198 = CmdGetSsdtTableInfo、207 = CmdInitSsdtTable、
 *     216 = CmdInitKernelMemoryContext —— 全部完好。
 *
 * 【已实现】路径 C 的合法 AES 包由 XpchBuildLicensePacket 构造
 *   （AES-128-ECB + MD5 + 时间窗），驱动侧 AesKeyExpansion 已按
 *   FIPS-197 还原；实机握手返回 OK、build=18362。
 */
BOOL XpchHandshake(PXPCH_CLIENT Client)
{
    ULONG Build = 0;
    ULONG Ssdt = 0;
    UCHAR Result = 0;
    UCHAR Packet[0x100];
    BOOL Built;
    BOOL Ok22;

    /* 走路径 C：0x100 字节合法许可包。
       这样既能把 GT[0x304] 置 1，又不会触发 AllocProcessInfoBuffer
       去清空命令表的槽 198..224，同时 GT[0x1E0]（ioctl 码）净变化为 0。 */
    Built = XpchBuildLicensePacket(Packet);
    Ok22 = FALSE;
    if (Built)
        Ok22 = XpchInvoke(Client, XPCH_CMD_QUERY_PROCESS_INFO,
                          Packet, sizeof(Packet), &Ssdt, sizeof(Ssdt), &Result);

    if (XpchInvoke(Client, XPCH_CMD_GET_MODULE_COUNT,
                   NULL, 0, &Build, sizeof(Build), &Result)) {
        if (Build != 0)
            return TRUE;
        printf("handshake: 0x24 returned 0 build (0x22: built=%d ok=%d ssdt=%lu)\n",
               Built, Ok22, Ssdt);
        return FALSE;
    }
    printf("handshake: 0x24 rejected (0x22: built=%d ok=%d ssdt=%lu result=%u)\n",
           Built, Ok22, Ssdt, (unsigned)Result);
    return FALSE;
}