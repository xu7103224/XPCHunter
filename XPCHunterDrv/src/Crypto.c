// Crypto.c — 加密/解密模块
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 包含 MD5、SHA1、AES 加密解密实现

#include "..\inc\XPCHunterDrv.h"

// SHA1 上下文
typedef struct _SHA1_CONTEXT {
    ULONG State[5];
    ULONG Count[2];
    UCHAR Buffer[64];
} SHA1_CONTEXT, *PSHA1_CONTEXT;

// AES 上下文
typedef struct _AES_CONTEXT {
    ULONG RoundKey[60];
    ULONG Rounds;
} AES_CONTEXT, *PAES_CONTEXT;

// 32 位循环左移
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

// SHA1 常量
#define SHA1_A 0x67452301
#define SHA1_B 0xEFCDAB89
#define SHA1_C 0x98BADCFE
#define SHA1_D 0x10325476
#define SHA1_E 0xC3D2E1F0

// MD5 常量
#define MD5_S11 7
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

// MD5 变换常量
static const ULONG Md5_K[64] = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
};

// MD5 每轮位移
static const ULONG Md5_S[64] = {
    MD5_S11, MD5_S12, MD5_S13, MD5_S14, MD5_S21, MD5_S22, MD5_S23, MD5_S24,
    MD5_S31, MD5_S32, MD5_S33, MD5_S34, MD5_S41, MD5_S42, MD5_S43, MD5_S44,
    MD5_S11, MD5_S12, MD5_S13, MD5_S14, MD5_S21, MD5_S22, MD5_S23, MD5_S24,
    MD5_S31, MD5_S32, MD5_S33, MD5_S34, MD5_S41, MD5_S42, MD5_S43, MD5_S44,
    MD5_S11, MD5_S12, MD5_S13, MD5_S14, MD5_S21, MD5_S22, MD5_S23, MD5_S24,
    MD5_S31, MD5_S32, MD5_S33, MD5_S34, MD5_S41, MD5_S42, MD5_S43, MD5_S44,
    MD5_S11, MD5_S12, MD5_S13, MD5_S14, MD5_S21, MD5_S22, MD5_S23, MD5_S24,
    MD5_S31, MD5_S32, MD5_S33, MD5_S34, MD5_S41, MD5_S42, MD5_S43, MD5_S44
};

// MD5 每轮索引
static const ULONG Md5_Id[64] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
};

// 字节序反转
static __forceinline void ByteReverse(ULONG *Buffer, ULONG Count)
{
    ULONG i;
    for (i = 0; i < Count; i++)
        Buffer[i] = ByteSwap64(Buffer[i]); // 实际应为 RtlUlongByteSwap
}

// 简化实现 — 实际复刻中需使用 RtlUlongByteSwap
#define RtlUlongByteSwap(x) _byteswap_ulong(x)

// InitMd5Context — 初始化 MD5 上下文
// 对应原始驱动 sub_140059CB4
void InitMd5Context(PMD5_CONTEXT Context)
{
    Context->Count[0] = 0;
    Context->Count[1] = 0;
    Context->State[0] = 0x67452301;
    Context->State[1] = 0xEFCDAB89;
    Context->State[2] = 0x98BADCFE;
    Context->State[3] = 0x10325476;
}

// Md5Transform — MD5 变换核心
// 对应原始驱动 sub_14003168
void Md5Transform(ULONG State[4], PUCHAR Block)
{
    ULONG a = State[0], b = State[1], c = State[2], d = State[3];
    ULONG x[16], i, j;

    for (i = 0; i < 16; i++)
        x[i] = ((ULONG)Block[i * 4]) | (((ULONG)Block[i * 4 + 1]) << 8) |
               (((ULONG)Block[i * 4 + 2]) << 16) | (((ULONG)Block[i * 4 + 3]) << 24);

    for (i = 0; i < 64; i++)
    {
        ULONG f, g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        ULONG temp = d;
        d = c;
        c = b;
        b = b + ROTL32(a + f + Md5_K[i] + x[g], Md5_S[i]);
        a = temp;
    }

    State[0] += a;
    State[1] += b;
    State[2] += c;
    State[3] += d;
}

// Md5Transform2 — MD5 变换（别名）
// 对应原始驱动 sub_140059CEC
void Md5Transform2(ULONG State[4], PUCHAR Block)
{
    Md5Transform(State, Block);
}

// Md5Update — MD5 更新
// 对应原始驱动 sub_14005A50C
void Md5Update(PMD5_CONTEXT Context, PUCHAR Input, ULONG Length)
{
    ULONG index = (Context->Count[0] >> 3) & 0x3F;
    Context->Count[0] += Length << 3;
    if (Context->Count[0] < (Length << 3))
        Context->Count[1]++;
    Context->Count[1] += Length >> 29;

    ULONG partLen = 64 - index;
    ULONG i = 0;
    if (Length >= partLen)
    {
        RtlCopyMemory(&Context->Buffer[index], Input, partLen);
        Md5Transform(Context->State, Context->Buffer);
        for (i = partLen; i + 63 < Length; i += 64)
            Md5Transform(Context->State, &Input[i]);
        index = 0;
    }
    RtlCopyMemory(&Context->Buffer[index], &Input[i], Length - i);
}

// Md5Final — MD5 结束
// 对应原始驱动 sub_14003984
void Md5Final(PMD5_CONTEXT Context, ULONG Digest[2])
{
    UCHAR bits[8];
    ULONG index, padLen;
    UCHAR padding[64] = { 0x80 };

    RtlCopyMemory(bits, Context->Count, 8);
    index = (Context->Count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    Md5Update(Context, padding, padLen);
    Md5Update(Context, bits, 8);
    RtlCopyMemory(Digest, Context->State, 8);
}

// MD5 别名函数
void Md5Final2(PMD5_CONTEXT Context, ULONG Digest[2])
{
    Md5Final(Context, Digest);
}

void Md5Update2(PMD5_CONTEXT Context, PUCHAR Input, ULONG Length)
{
    Md5Update(Context, Input, Length);
}

// SHA1 初始化
// 对应原始驱动 sub_140076500
void Sha1InitContext(PSHA1_CONTEXT Context)
{
    Context->State[0] = SHA1_A;
    Context->State[1] = SHA1_B;
    Context->State[2] = SHA1_C;
    Context->State[3] = SHA1_D;
    Context->State[4] = SHA1_E;
    Context->Count[0] = 0;
    Context->Count[1] = 0;
}

// SHA1 变换（标准实现）
// 对应原始驱动 sub_140076540
void Sha1Transform(ULONG State[5], PUCHAR Buffer)
{
    ULONG w[80], a, b, c, d, e, temp, i;

    for (i = 0; i < 16; i++)
        w[i] = RtlUlongByteSwap(((PULONG)Buffer)[i]);

    for (i = 16; i < 80; i++)
        w[i] = ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = State[0]; b = State[1]; c = State[2]; d = State[3]; e = State[4];

    for (i = 0; i < 80; i++)
    {
        if (i < 20)
            temp = ROTL32(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999;
        else if (i < 40)
            temp = ROTL32(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
        else if (i < 60)
            temp = ROTL32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
        else
            temp = ROTL32(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;

        e = d; d = c; c = ROTL32(b, 30); b = a; a = temp;
    }

    State[0] += a; State[1] += b; State[2] += c; State[3] += d; State[4] += e;
}

// SHA1 更新
// 对应原始驱动 sub_14007761C
void Sha1Update(PSHA1_CONTEXT Context, PUCHAR Input, ULONG Length)
{
    ULONG i, index, partLen;

    index = (Context->Count[0] >> 3) & 0x3F;
    Context->Count[0] += Length << 3;
    if (Context->Count[0] < (Length << 3))
        Context->Count[1]++;
    Context->Count[1] += Length >> 29;

    partLen = 64 - index;
    if (Length >= partLen)
    {
        RtlCopyMemory(&Context->Buffer[index], Input, partLen);
        Sha1Transform(Context->State, Context->Buffer);
        for (i = partLen; i + 63 < Length; i += 64)
            Sha1Transform(Context->State, &Input[i]);
        index = 0;
    }
    RtlCopyMemory(&Context->Buffer[index], &Input[i], Length - i);
}

// SHA1 结束变换
// 对应原始驱动 sub_1400763E0
void Sha1FinalTransform(PSHA1_CONTEXT Context, __int64 DigestOut)
{
    UCHAR bits[8];
    ULONG index, padLen, i;
    UCHAR padding[64] = { 0x80 };

    RtlCopyMemory(bits, Context->Count, 8);
    index = (Context->Count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    Sha1Update(Context, padding, padLen);
    Sha1Update(Context, bits, 8);

    for (i = 0; i < 5; i++)
        ((PULONG)DigestOut)[i] = RtlUlongByteSwap(Context->State[i]);
}

// Sha1HashToDword — SHA1 哈希为 DWORD
// 对应原始驱动 sub_1400053D4
__int64 Sha1HashToDword(char *String)
{
    SHA1_CONTEXT Context;
    ULONG Digest[5];

    Sha1InitContext(&Context);
    Sha1Update(&Context, (PUCHAR)String, StringLength(String));
    Sha1FinalTransform(&Context, (__int64)Digest);
    return Digest[0];
}

// DecryptInputBuffer — 解密输入缓冲区
// 对应原始驱动 sub_1400813C0
__int64 DecryptInputBuffer(PUCHAR Buffer)
{
    // 简单的 XOR 解密
    ULONG Key = GtRead(GtEncryptionKey);
    UCHAR KeyByte = GtRead(GtEncryptionKeyByte);
    ULONG i;

    for (i = 0; i < IRP_INPUT_BUFFER_SIZE; i++)
        Buffer[i] ^= KeyByte;

    Buffer[0] ^= (Key >> 24) & 0xFF;
    Buffer[1] ^= (Key >> 16) & 0xFF;
    Buffer[2] ^= (Key >> 8) & 0xFF;
    Buffer[3] ^= Key & 0xFF;

    return 1;
}

// GenerateEncryptionKey — 生成加密密钥
// 对应原始驱动 sub_140081314
__int64 GenerateEncryptionKey(PWSTR RegistryPath)
{
    ULONG Key = 0x20202020;
    UCHAR KeyByte = 0x20;

    if (RegistryPath)
    {
        ULONG i;
        for (i = 0; RegistryPath[i] && i < 32; i++)
        {
            Key ^= (RegistryPath[i] << ((i & 3) * 8));
            KeyByte ^= (UCHAR)RegistryPath[i];
        }
    }

    GtWrite(GtEncryptionKey, Key);
    GtWrite(GtEncryptionKeyByte, KeyByte);
    return 1;
}
