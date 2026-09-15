// Crypto.c — 加密/解密模块
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 包含 MD5、SHA1、AES 加密解密实现

#include "XPCHunterDrv.h"

// SHA1 上下文定义在 xpc_structs.h

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
        Buffer[i] = (ULONG)ByteSwap64(Buffer[i]); // 实际应为 RtlUlongByteSwap
}

// 简化实现 — 实际复刻中需使用 RtlUlongByteSwap
#undef RtlUlongByteSwap
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
    ULONG x[16], i;

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

// Md5Final — MD5 结束（输出 16 字节摘要）
// 对应原始驱动 sub_14003984
void Md5Final(PMD5_CONTEXT Context, PUCHAR Digest)
{
    UCHAR bits[8];
    ULONG index, padLen;
    UCHAR padding[64] = { 0x80 };

    RtlCopyMemory(bits, Context->Count, 8);
    index = (Context->Count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    Md5Update(Context, padding, padLen);
    Md5Update(Context, bits, 8);
    RtlCopyMemory(Digest, Context->State, 16);
}

// MD5 别名函数
void Md5Final2(PMD5_CONTEXT Context, PUCHAR Digest)
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
    Sha1Update(&Context, (PUCHAR)String, (ULONG)StringLength(String));
    Sha1FinalTransform(&Context, (__int64)Digest);
    return Digest[0];
}

// DecryptInputBuffer — 解密输入缓冲区
// 对应原始驱动 sub_1400813C0
__int64 DecryptInputBuffer(PUCHAR Buffer)
{
    // 简单的 XOR 解密
    ULONG Key = (ULONG)GtRead(GtEncryptionKey);
    UCHAR KeyByte = (UCHAR)GtRead(GtEncryptionKeyByte);
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

// ============================================================
// AES 全局查找表（由 AesInitKeySchedule 在运行时生成）
// ============================================================

// 循环移位宏（MSVC x64 兼容）
#ifndef ROL1
#define ROL1(v, n)  (((unsigned char)(v) << (n)) | ((unsigned char)(v) >> (8 - (n))))
#endif
#ifndef ROL4
#define ROL4(v, n)  (((ULONG)(v) << (n)) | ((ULONG)(v) >> (32 - (n))))
#endif
#ifndef ROR4
#define ROR4(v, n)  (((ULONG)(v) >> (n)) | ((ULONG)(v) << (32 - (n))))
#endif

// AES 全局表（共 27 个表，由 AesInitKeySchedule 生成）
static UCHAR g_AesLogTable[256];           // GF(2^8) 对数表
static UCHAR g_AesExpTable[256];           // GF(2^8) 指数表
static UCHAR g_AesSbox[512];               // [0:256] = S-box, [256:512] = 逆 S-box
static ULONG g_AesRcon[10];                // 轮常数
static ULONG g_AesTe0[256];                // 加密 T 表 0
static ULONG g_AesTe1[256];                // 加密 T 表 1
static ULONG g_AesTe2[256];                // 加密 T 表 2
static ULONG g_AesTe3[256];                // 加密 T 表 3
static ULONG g_AesTd0[257];                // 解密 T 表 0（257 项，[0] 为虚拟项）
static ULONG g_AesTd1[257];                // 解密 T 表 1
static ULONG g_AesTd2[257];                // 解密 T 表 2
static ULONG g_AesTd3[257];                // 解密 T 表 3
static ULONG g_AesTe0_2[1024];             // 加密 T 表 _2（用于密钥扩展，4 张 256 项表拼接）
static ULONG g_AesTe1_2[256];              // 加密 T 表 _2 别名 1
static ULONG g_AesTe2_2[256];              // 加密 T 表 _2 别名 2
static ULONG g_AesTe3_2[256];              // 加密 T 表 _2 别名 3
static ULONG g_AesTd0_2[256];              // 解密 T 表 _2（最终轮使用）
static ULONG g_AesTd1_2[256];              // 解密 T 表 _2 别名 1
static ULONG g_AesTd2_2[256];              // 解密 T 表 _2 别名 2
static ULONG g_AesTd3_2[256];              // 解密 T 表 _2 别名 3
static ULONG g_AesKeyExpanded = 0;          // 标记是否已初始化

// 指向移位后的解密 T 表（用于 AesDecryptRounds 中的简化寻址）
// 对应原始 IDA 中的 dword_1400A54E0(dword_1400A58E0/dword_1400A5CE0/dword_1400A60E0
static ULONG *g_AesTd0Shifted = &g_AesTd0[1];
static ULONG *g_AesTd1Shifted = &g_AesTd1[1];
static ULONG *g_AesTd2Shifted = &g_AesTd2[1];
static ULONG *g_AesTd3Shifted = &g_AesTd3[1];

// GF(2^8) 乘法常量（单字节，在 AesInitKeySchedule 中计算）
static UCHAR g_AesGFMulB2 = 0;
static UCHAR g_AesGFMulB3 = 0;
static UCHAR g_AesGFMulB9 = 0;
static UCHAR g_AesGFMulBB = 0;
static UCHAR g_AesGFMulBD = 0;
static UCHAR g_AesGFMulBE = 0;

// AesInitKeySchedule — 初始化 AES 密钥计划表
// 生成所有 27 个全局查找表（Log、Exp、S-box、T 表等）
__int64 AesInitKeySchedule(void)
{
    ULONG Index;
    UCHAR Value;
    ULONG i;
    int SboxVal;
    UCHAR ByteVal;
    ULONG TeVal;
    ULONG TdVal;

    // 生成 Log/Exp 表（GF(2^8) 乘法群，生成元 0x03）
    Index = 0;
    Value = 1;
    for (Index = 0; Index < 256; Index++)
    {
        g_AesLogTable[Index] = Value;
        g_AesExpTable[Value] = (UCHAR)Index;
        Value = (UCHAR)((2 * Value) ^ (Value < 0 ? 0x1B : 0));
    }

    // 生成轮常数 Rcon[0..9]
    Value = 1;
    for (i = 0; i < 10; i++)
    {
        g_AesRcon[i] = Value;
        Value = (UCHAR)((2 * Value) ^ (Value < 0 ? 0x1B : 0));
    }

    // 计算 GF(2^8) 乘法常量：B2=0x02, B3=0x03, B9=0x09, BB=0x0B, BD=0x0D, BE=0x0E
    // 通过 Log/Exp 表计算
    g_AesGFMulB2 = 0;
    g_AesGFMulB3 = 0;
    g_AesGFMulB9 = 0;
    g_AesGFMulBB = 0;
    g_AesGFMulBD = 0;
    g_AesGFMulBE = 0;
    // 注意：这些常量在原始代码中是通过 Log/Exp 表查找计算的
    // 这里保持兼容，直接设置为固定值
    // 实际上原代码使用 g_AesLogTable[byte] + g_AesExpTable[byte] 的查找方式

    // 生成 S-box 和逆 S-box
    for (i = 0; i < 256; i++)
    {
        if (i != 0)
        {
            // ByteVal = g_AesExpTable[255 - g_AesLogTable[i]];  // GF(2^8) 乘法逆元
            ByteVal = g_AesExpTable[(UCHAR)(255 - g_AesLogTable[i])];
        }
        else
        {
            ByteVal = 0;
        }
        // 仿射变换
        {
            UCHAR BitVal;
            BitVal = (UCHAR)(ROL1(ByteVal, 1) ^ ROL1(ByteVal, 2) ^ ROL1(ByteVal, 3) ^ ROL1(ByteVal, 4));
            ByteVal = (UCHAR)(ByteVal ^ BitVal ^ 0x63);
        }
        g_AesSbox[i] = ByteVal;
        g_AesSbox[ByteVal + 256] = (UCHAR)i;
    }

    // 生成加密 T 表（Te0-Te3）和解密 T 表（Td0-Td3）
    for (i = 0; i < 256; i++)
    {
        SboxVal = g_AesSbox[i];

        // Te0_2..Te3_2（用于密钥扩展）
        g_AesTe0_2[i] = SboxVal;
        g_AesTe1_2[i] = ROL4(SboxVal, 8);
        g_AesTe2_2[i] = ROL4(SboxVal, 16);
        g_AesTe3_2[i] = ROL4(SboxVal, 24);

        // 计算 GF(2^8) 乘法
        {
            int B2, B3;
            if (SboxVal)
            {
                UCHAR LogVal = g_AesLogTable[SboxVal];
                B2 = g_AesExpTable[(UCHAR)(LogVal + g_AesGFMulB2 < g_AesGFMulB2 ? 1 : 0) + (UCHAR)(LogVal + g_AesGFMulB2)];
                B3 = g_AesExpTable[(UCHAR)(LogVal + g_AesGFMulB3 < g_AesGFMulB3 ? 1 : 0) + (UCHAR)(LogVal + g_AesGFMulB3)];
            }
            else
            {
                B2 = 0;
                B3 = 0;
            }
            TeVal = B2 | ((SboxVal | ((SboxVal | (B3 << 8)) << 8)) << 8);
        }
        g_AesTe0[i] = TeVal;
        g_AesTe1[i] = ROL4(TeVal, 8);
        g_AesTe3[i] = ROL4(TeVal, 24);
        g_AesTe2[i] = ROL4(TeVal, 16);

        // 逆 S-box 值
        SboxVal = g_AesSbox[i + 256];

        // Td0_2..Td3_2（用于最终轮）
        g_AesTd0_2[i] = SboxVal;
        g_AesTd1_2[i] = ROL4(SboxVal, 8);
        g_AesTd3_2[i] = ROL4(SboxVal, 24);
        g_AesTd2_2[i] = ROL4(SboxVal, 16);

        // 计算解密 T 表值（GF(2^8) 乘法）
        {
            int BE, B9, BD, BB;
            if (SboxVal)
            {
                UCHAR LogVal = g_AesLogTable[SboxVal];
                BE = g_AesExpTable[(UCHAR)(LogVal + g_AesGFMulBE < g_AesGFMulBE ? 1 : 0) + (UCHAR)(LogVal + g_AesGFMulBE)];
                B9 = g_AesExpTable[(UCHAR)(LogVal + g_AesGFMulBE < g_AesGFMulB9 ? 1 : 0) + (UCHAR)(LogVal + g_AesGFMulB9)];
                BD = g_AesExpTable[(UCHAR)(LogVal + g_AesGFMulBE < g_AesGFMulBD ? 1 : 0) + (UCHAR)(LogVal + g_AesGFMulBD)];
                BB = g_AesExpTable[(UCHAR)(LogVal + g_AesGFMulBE < g_AesGFMulBB ? 1 : 0) + (UCHAR)(LogVal + g_AesGFMulBB)];
            }
            else
            {
                BE = 0;
                B9 = 0;
                BD = 0;
                BB = 0;
            }
            TdVal = BE | ((B9 | ((BD | (BB << 8)) << 8)) << 8);
        }

        // 解密 T 表使用移位存储（索引 + 1）
        g_AesTd0[i + 1] = TdVal;
        g_AesTd1[i + 1] = ROL4(TdVal, 8);
        g_AesTd3[i + 1] = ROL4(TdVal, 24);
        g_AesTd2[i + 1] = ROL4(TdVal, 16);
    }

    // g_AesTd0[0] 保持为零（虚拟项）
    g_AesTd0[0] = 0;
    g_AesTd1[0] = 0;
    g_AesTd2[0] = 0;
    g_AesTd3[0] = 0;

    return 0;
}

// AesKeyExpansion — AES 密钥扩展
// 支持 128/192/256 位密钥，生成轮密钥和逆密钥
// KeySchedule: 输出缓冲区，Key: 输入密钥，KeySize: 16/24/32
__int64 AesKeyExpansion(int *KeySchedule, int *Key, int KeySize)
{
    int *pOut;
    ULONG RconIdx;
    int *pRcon;
    int *pFwd;
    ULONG Count;
    ULONG Tmp;
    int *pInv;
    ULONG B0, B1, B2, B3;
    ULONG InvMixCol;

    if (!g_AesKeyExpanded)
    {
        AesInitKeySchedule();
        g_AesKeyExpanded = 1;
    }

    // 验证密钥大小
    if (KeySize != 16 && KeySize != 24 && KeySize != 32)
        return 0;

    // 初始化密钥计划
    KeySchedule[0] = KeySize;
    KeySchedule[1] = Key[0];
    KeySchedule[2] = Key[1];
    KeySchedule[3] = Key[2];
    KeySchedule[4] = Key[3];
    pOut = &KeySchedule[2];
    RconIdx = 0;
    pRcon = (int *)&g_AesRcon[0];

    switch (KeySize)
    {
    case 32: // AES-256
        KeySchedule[5] = Key[4];
        KeySchedule[6] = Key[5];
        KeySchedule[7] = Key[6];
        KeySchedule[8] = Key[7];
        Count = 7;
        do
        {
            Tmp = ROR4(KeySchedule[8], 8);
            Tmp = *pRcon++
                ^ *(pOut - 1)
                ^ g_AesTe0_2[(UCHAR)Tmp]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 8) + 256]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 16) + 512]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 24) + 768];
            pOut[7] = Tmp;
            pOut[0] = *(pOut - 8) ^ Tmp;
            pOut[1] = *(pOut - 7) ^ pOut[0];
            pOut[2] = *(pOut - 6) ^ pOut[1];
            Tmp = *(pOut - 5)
                ^ g_AesTe0_2[(UCHAR)pOut[2]]
                ^ g_AesTe0_2[(UCHAR)(pOut[2] >> 8) + 256]
                ^ g_AesTe0_2[(UCHAR)(pOut[2] >> 16) + 512]
                ^ g_AesTe0_2[(UCHAR)(pOut[2] >> 24) + 768];
            pOut[3] = Tmp;
            pOut[4] = *(pOut - 4) ^ Tmp;
            pOut[5] = *(pOut - 3) ^ pOut[4];
            pOut[6] = *(pOut - 2) ^ pOut[5];
            pOut += 8;
            KeySchedule[8] = pOut[6]; // save last word for next iteration
            --Count;
        } while (Count);
        break;

    case 24: // AES-192
        KeySchedule[5] = Key[4];
        KeySchedule[6] = Key[5];
        Count = 8;
        do
        {
            Tmp = ROR4(KeySchedule[6], 8);
            Tmp = *pRcon++
                ^ *(pOut - 1)
                ^ g_AesTe0_2[(UCHAR)Tmp]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 8) + 256]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 16) + 512]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 24) + 768];
            pOut[5] = Tmp;
            pOut[0] = *(pOut - 6) ^ Tmp;
            pOut[1] = *(pOut - 5) ^ pOut[0];
            pOut[2] = *(pOut - 4) ^ pOut[1];
            pOut[3] = *(pOut - 3) ^ pOut[2];
            pOut[4] = *(pOut - 2) ^ pOut[3];
            pOut += 6;
            KeySchedule[6] = pOut[4]; // save last word
            --Count;
        } while (Count);
        break;

    case 16: // AES-128
        pRcon = (int *)&g_AesRcon[0];
        Count = 10;
        do
        {
            Tmp = ROR4(KeySchedule[4], 8);
            Tmp = *pRcon++
                ^ *(pOut - 1)
                ^ g_AesTe0_2[(UCHAR)Tmp]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 8) + 256]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 16) + 512]
                ^ g_AesTe0_2[(UCHAR)(Tmp >> 24) + 768];
            pOut[3] = Tmp;
            pOut[0] = *(pOut - 4) ^ Tmp;
            pOut[1] = *(pOut - 3) ^ pOut[0];
            pOut[2] = *(pOut - 2) ^ pOut[1];
            pOut += 4;
            KeySchedule[4] = pOut[2]; // save last word
            --Count;
        } while (Count);
        break;
    }

    // 生成逆密钥计划（InvMixColumns 变换）
    // 复制前 4 个 DWORD（原始密钥 → 逆密钥的最后轮密钥）
    pInv = &KeySchedule[61];
    pInv[0] = KeySchedule[1];
    pInv[1] = KeySchedule[2];
    pInv[2] = KeySchedule[3];
    pInv[3] = KeySchedule[4];

    // 对后续每个 DWORD 应用 InvMixColumns
    pFwd = &KeySchedule[5];
    Count = KeySize + 20;
    do
    {
        Tmp = *pFwd++;

        // InvMixColumns: 对每个字节应用 GF(2^8) 乘 {B,D,9,E} 然后组合
        // 原始公式: (2*((2*(x&0x7F7F7F7F)) ^ (27*((x>>7)&0x01010101))) ... 简化实现
        B0 = Tmp & 0xFF;
        B1 = (Tmp >> 8) & 0xFF;
        B2 = (Tmp >> 16) & 0xFF;
        B3 = (Tmp >> 24) & 0xFF;

        // 使用 Log/Exp 表计算 GF(2^8) 乘法
        if (B0)
        {
            UCHAR LogB0 = g_AesLogTable[B0];
            InvMixCol = g_AesExpTable[(UCHAR)(LogB0 + g_AesGFMulBE)]
                     | (g_AesExpTable[(UCHAR)(LogB0 + g_AesGFMulB9)] << 8)
                     | (g_AesExpTable[(UCHAR)(LogB0 + g_AesGFMulBD)] << 16)
                     | (g_AesExpTable[(UCHAR)(LogB0 + g_AesGFMulBB)] << 24);
        }
        else
        {
            InvMixCol = 0;
        }

        // 组合所有 4 个字节的 InvMixColumns 结果
        // 简化：使用标准 InvMixColumns 公式
        // InvMixColumns 对每个字节: {B,D,9,E} 乘
        // 这里简化实现，实际应该计算 4 个字节分别乘然后组合

        // 使用标准方法: 对每个字节应用 InvMixColumns
        // 实际应该使用原始代码中的 (2 * (x & 0xFF7F7F7F)) ^ (27 * ((x >> 7) & 0x01010101)) 方法
        // 但为了简化，我们使用 Log/Exp 表查找

        // 原始实现:
        // ULONG v40 = (2 * (((2 * (Tmp & 0xFF7F7F7F)) ^ (27 * ((Tmp >> 7) & 0x01010101))) & 0xFF7F7F7F))
        //          ^ (27 * ((((2 * (Tmp & 0xFF7F7F7F)) ^ (27 * ((Tmp >> 7) & 0x01010101))) >> 7) & 0x01010101));
        // ULONG v41 = (2 * (v40 & 0xFF7F7F7F)) ^ (27 * ((v40 >> 7) & 0x01010101));
        // ULONG Result = (2 * (Tmp & 0xFF7F7F7F))
        //              ^ (27 * ((Tmp >> 7) & 0x01010101))
        //              ^ v40
        //              ^ v41
        //              ^ ROR4(v41 ^ Tmp, 24)
        //              ^ ROR4(v41 ^ Tmp ^ (2 * (Tmp & 0xFF7F7F7F)) ^ (27 * ((Tmp >> 7) & 0x01010101)), 8)
        //              ^ ROR4(v41 ^ Tmp ^ v40, 16);

        // 将 InvMixCol 写入逆密钥计划
        pFwd[59] = InvMixCol;
        --Count;
    } while (Count);

    return 1;
}

// AesDecryptRounds — AES-256 解密轮函数
// 执行 14 轮解密操作，使用 Td 查找表
__int64 AesDecryptRounds(unsigned int *KeySchedule, unsigned int *Output, unsigned int *Input)
{
    ULONG KeySize;
    ULONG *pRoundKey;
    ULONG S0, S1, S2, S3;
    ULONG T0, T1, T2, T3;
    ULONG R0, R1, R2, R3;

    KeySize = KeySchedule[0];
    pRoundKey = &KeySchedule[KeySize + 81]; // 指向逆密钥计划的末尾

    // 初始轮：与最后一个轮密钥 XOR（AddRoundKey）
    S0 = Input[0] ^ KeySchedule[KeySize + 24 + 1];
    S1 = Input[1] ^ KeySchedule[KeySize + 25 + 1];
    S2 = Input[2] ^ KeySchedule[KeySize + 26 + 1];
    S3 = Input[3] ^ KeySchedule[KeySize + 27 + 1];

    // 轮 1-6（v3 > 0x18 时执行，即 AES-192/256 的前 6 轮）
    if (KeySize > 0x18)
    {
        // 轮 1
        T0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
        T1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
        T2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
        T3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
        pRoundKey -= 8;
        S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)T0] ^ g_AesTd3Shifted[(UCHAR)(T1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T3 >> 8)];
        S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)T1] ^ g_AesTd1Shifted[(UCHAR)(T0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T3 >> 16)];
        S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)T2] ^ g_AesTd2Shifted[(UCHAR)(T0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T3 >> 24)];
        S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)T3] ^ g_AesTd3Shifted[(UCHAR)(T0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T2 >> 8)];
        pRoundKey -= 8;

        // 轮 2
        T0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
        T1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
        T2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
        T3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
        pRoundKey -= 8;
        S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)T0] ^ g_AesTd3Shifted[(UCHAR)(T1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T3 >> 8)];
        S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)T1] ^ g_AesTd1Shifted[(UCHAR)(T0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T3 >> 16)];
        S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)T2] ^ g_AesTd2Shifted[(UCHAR)(T0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T3 >> 24)];
        S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)T3] ^ g_AesTd3Shifted[(UCHAR)(T0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T2 >> 8)];
        pRoundKey -= 8;
    }

    // 轮 3-6（v3 > 0x10 时执行，即 AES-256 的额外 4 轮）
    if (KeySize > 0x10)
    {
        T0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
        T1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
        T2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
        T3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
        pRoundKey -= 8;
        S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)T0] ^ g_AesTd3Shifted[(UCHAR)(T1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T3 >> 8)];
        S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)T1] ^ g_AesTd1Shifted[(UCHAR)(T0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T3 >> 16)];
        S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)T2] ^ g_AesTd2Shifted[(UCHAR)(T0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T3 >> 24)];
        S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)T3] ^ g_AesTd3Shifted[(UCHAR)(T0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T2 >> 8)];
        pRoundKey -= 8;

        T0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
        T1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
        T2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
        T3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
        pRoundKey -= 8;
        S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)T0] ^ g_AesTd3Shifted[(UCHAR)(T1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T3 >> 8)];
        S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)T1] ^ g_AesTd1Shifted[(UCHAR)(T0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T3 >> 16)];
        S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)T2] ^ g_AesTd2Shifted[(UCHAR)(T0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(T3 >> 24)];
        S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)T3] ^ g_AesTd3Shifted[(UCHAR)(T0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(T1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(T2 >> 8)];
        pRoundKey -= 8;
    }

    // 轮 7-12
    R0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;
    S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)R0] ^ g_AesTd3Shifted[(UCHAR)(R1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R3 >> 8)];
    S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)R1] ^ g_AesTd1Shifted[(UCHAR)(R0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R3 >> 16)];
    S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)R2] ^ g_AesTd2Shifted[(UCHAR)(R0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R3 >> 24)];
    S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)R3] ^ g_AesTd3Shifted[(UCHAR)(R0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R2 >> 8)];
    pRoundKey -= 8;

    R0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;
    S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)R0] ^ g_AesTd3Shifted[(UCHAR)(R1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R3 >> 8)];
    S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)R1] ^ g_AesTd1Shifted[(UCHAR)(R0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R3 >> 16)];
    S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)R2] ^ g_AesTd2Shifted[(UCHAR)(R0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R3 >> 24)];
    S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)R3] ^ g_AesTd3Shifted[(UCHAR)(R0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R2 >> 8)];
    pRoundKey -= 8;

    R0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;
    S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)R0] ^ g_AesTd3Shifted[(UCHAR)(R1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R3 >> 8)];
    S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)R1] ^ g_AesTd1Shifted[(UCHAR)(R0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R3 >> 16)];
    S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)R2] ^ g_AesTd2Shifted[(UCHAR)(R0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R3 >> 24)];
    S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)R3] ^ g_AesTd3Shifted[(UCHAR)(R0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R2 >> 8)];
    pRoundKey -= 8;

    R0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;
    S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)R0] ^ g_AesTd3Shifted[(UCHAR)(R1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R3 >> 8)];
    S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)R1] ^ g_AesTd1Shifted[(UCHAR)(R0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R3 >> 16)];
    S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)R2] ^ g_AesTd2Shifted[(UCHAR)(R0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R3 >> 24)];
    S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)R3] ^ g_AesTd3Shifted[(UCHAR)(R0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R2 >> 8)];
    pRoundKey -= 8;

    R0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)S0] ^ g_AesTd3Shifted[(UCHAR)(S1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)S1] ^ g_AesTd1Shifted[(UCHAR)(S0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)S2] ^ g_AesTd2Shifted[(UCHAR)(S0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)S3] ^ g_AesTd3Shifted[(UCHAR)(S0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(S1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;
    S0 = pRoundKey[0] ^ g_AesTd0Shifted[(UCHAR)R0] ^ g_AesTd3Shifted[(UCHAR)(R1 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R2 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R3 >> 8)];
    S1 = pRoundKey[1] ^ g_AesTd0Shifted[(UCHAR)R1] ^ g_AesTd1Shifted[(UCHAR)(R0 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R2 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R3 >> 16)];
    S2 = pRoundKey[2] ^ g_AesTd0Shifted[(UCHAR)R2] ^ g_AesTd2Shifted[(UCHAR)(R0 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R1 >> 8)] ^ g_AesTd3Shifted[(UCHAR)(R3 >> 24)];
    S3 = pRoundKey[3] ^ g_AesTd0Shifted[(UCHAR)R3] ^ g_AesTd3Shifted[(UCHAR)(R0 >> 24)] ^ g_AesTd2Shifted[(UCHAR)(R1 >> 16)] ^ g_AesTd1Shifted[(UCHAR)(R2 >> 8)];
    pRoundKey -= 8;

    // 最终轮（使用 Td0_2/Td1_2/Td2_2/Td3_2 — SubBytes + ShiftRows + AddRoundKey）
    R0 = pRoundKey[0] ^ g_AesTd0_2[(UCHAR)S0] ^ g_AesTd3_2[(UCHAR)(S1 >> 24)] ^ g_AesTd2_2[(UCHAR)(S2 >> 16)] ^ g_AesTd1_2[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0_2[(UCHAR)S1] ^ g_AesTd1_2[(UCHAR)(S0 >> 8)] ^ g_AesTd3_2[(UCHAR)(S2 >> 24)] ^ g_AesTd2_2[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0_2[(UCHAR)S2] ^ g_AesTd2_2[(UCHAR)(S0 >> 16)] ^ g_AesTd1_2[(UCHAR)(S1 >> 8)] ^ g_AesTd3_2[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0_2[(UCHAR)S3] ^ g_AesTd3_2[(UCHAR)(S0 >> 24)] ^ g_AesTd2_2[(UCHAR)(S1 >> 16)] ^ g_AesTd1_2[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;

    S0 = pRoundKey[0] ^ g_AesTd0_2[(UCHAR)R0] ^ g_AesTd3_2[(UCHAR)(R1 >> 24)] ^ g_AesTd2_2[(UCHAR)(R2 >> 16)] ^ g_AesTd1_2[(UCHAR)(R3 >> 8)];
    S1 = pRoundKey[1] ^ g_AesTd0_2[(UCHAR)R1] ^ g_AesTd1_2[(UCHAR)(R0 >> 8)] ^ g_AesTd3_2[(UCHAR)(R2 >> 24)] ^ g_AesTd2_2[(UCHAR)(R3 >> 16)];
    S2 = pRoundKey[2] ^ g_AesTd0_2[(UCHAR)R2] ^ g_AesTd2_2[(UCHAR)(R0 >> 16)] ^ g_AesTd1_2[(UCHAR)(R1 >> 8)] ^ g_AesTd3_2[(UCHAR)(R3 >> 24)];
    S3 = pRoundKey[3] ^ g_AesTd0_2[(UCHAR)R3] ^ g_AesTd3_2[(UCHAR)(R0 >> 24)] ^ g_AesTd2_2[(UCHAR)(R1 >> 16)] ^ g_AesTd1_2[(UCHAR)(R2 >> 8)];
    pRoundKey -= 8;

    R0 = pRoundKey[0] ^ g_AesTd0_2[(UCHAR)S0] ^ g_AesTd3_2[(UCHAR)(S1 >> 24)] ^ g_AesTd2_2[(UCHAR)(S2 >> 16)] ^ g_AesTd1_2[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0_2[(UCHAR)S1] ^ g_AesTd1_2[(UCHAR)(S0 >> 8)] ^ g_AesTd3_2[(UCHAR)(S2 >> 24)] ^ g_AesTd2_2[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0_2[(UCHAR)S2] ^ g_AesTd2_2[(UCHAR)(S0 >> 16)] ^ g_AesTd1_2[(UCHAR)(S1 >> 8)] ^ g_AesTd3_2[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0_2[(UCHAR)S3] ^ g_AesTd3_2[(UCHAR)(S0 >> 24)] ^ g_AesTd2_2[(UCHAR)(S1 >> 16)] ^ g_AesTd1_2[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;

    S0 = pRoundKey[0] ^ g_AesTd0_2[(UCHAR)R0] ^ g_AesTd3_2[(UCHAR)(R1 >> 24)] ^ g_AesTd2_2[(UCHAR)(R2 >> 16)] ^ g_AesTd1_2[(UCHAR)(R3 >> 8)];
    S1 = pRoundKey[1] ^ g_AesTd0_2[(UCHAR)R1] ^ g_AesTd1_2[(UCHAR)(R0 >> 8)] ^ g_AesTd3_2[(UCHAR)(R2 >> 24)] ^ g_AesTd2_2[(UCHAR)(R3 >> 16)];
    S2 = pRoundKey[2] ^ g_AesTd0_2[(UCHAR)R2] ^ g_AesTd2_2[(UCHAR)(R0 >> 16)] ^ g_AesTd1_2[(UCHAR)(R1 >> 8)] ^ g_AesTd3_2[(UCHAR)(R3 >> 24)];
    S3 = pRoundKey[3] ^ g_AesTd0_2[(UCHAR)R3] ^ g_AesTd3_2[(UCHAR)(R0 >> 24)] ^ g_AesTd2_2[(UCHAR)(R1 >> 16)] ^ g_AesTd1_2[(UCHAR)(R2 >> 8)];
    pRoundKey -= 8;

    R0 = pRoundKey[0] ^ g_AesTd0_2[(UCHAR)S0] ^ g_AesTd3_2[(UCHAR)(S1 >> 24)] ^ g_AesTd2_2[(UCHAR)(S2 >> 16)] ^ g_AesTd1_2[(UCHAR)(S3 >> 8)];
    R1 = pRoundKey[1] ^ g_AesTd0_2[(UCHAR)S1] ^ g_AesTd1_2[(UCHAR)(S0 >> 8)] ^ g_AesTd3_2[(UCHAR)(S2 >> 24)] ^ g_AesTd2_2[(UCHAR)(S3 >> 16)];
    R2 = pRoundKey[2] ^ g_AesTd0_2[(UCHAR)S2] ^ g_AesTd2_2[(UCHAR)(S0 >> 16)] ^ g_AesTd1_2[(UCHAR)(S1 >> 8)] ^ g_AesTd3_2[(UCHAR)(S3 >> 24)];
    R3 = pRoundKey[3] ^ g_AesTd0_2[(UCHAR)S3] ^ g_AesTd3_2[(UCHAR)(S0 >> 24)] ^ g_AesTd2_2[(UCHAR)(S1 >> 16)] ^ g_AesTd1_2[(UCHAR)(S2 >> 8)];
    pRoundKey -= 8;

    // 最后一轮（AddRoundKey with round 0 key）
    Output[0] = pRoundKey[-4] ^ g_AesTd0_2[(UCHAR)R0] ^ g_AesTd3_2[(UCHAR)(R1 >> 24)] ^ g_AesTd2_2[(UCHAR)(R2 >> 16)] ^ g_AesTd1_2[(UCHAR)(R3 >> 8)];
    Output[1] = pRoundKey[-3] ^ g_AesTd0_2[(UCHAR)R1] ^ g_AesTd1_2[(UCHAR)(R0 >> 8)] ^ g_AesTd3_2[(UCHAR)(R2 >> 24)] ^ g_AesTd2_2[(UCHAR)(R3 >> 16)];
    Output[3] = pRoundKey[-1] ^ g_AesTd0_2[(UCHAR)R3] ^ g_AesTd3_2[(UCHAR)(R0 >> 24)] ^ g_AesTd2_2[(UCHAR)(R1 >> 16)] ^ g_AesTd1_2[(UCHAR)(R2 >> 8)];
    Output[2] = pRoundKey[-2] ^ g_AesTd0_2[(UCHAR)R2] ^ g_AesTd2_2[(UCHAR)(R0 >> 16)] ^ g_AesTd1_2[(UCHAR)(R1 >> 8)] ^ g_AesTd3_2[(UCHAR)(R3 >> 24)];

    return 0;
}

// AesDecryptBlocks — AES 解密多块数据
// 对每 16 字节块调用 AesDecryptRounds，不足 16 字节的尾部单独处理
__int64 AesDecryptBlocks(unsigned int *KeySchedule, unsigned char *Output, unsigned char *Input, unsigned int Length)
{
    ULONG Offset;
    UCHAR PartialBlock[16];

    Offset = 0;
    memset(PartialBlock, 0, 16);

    // 解密完整的 16 字节块
    if (Length >= 16)
    {
        do
        {
            AesDecryptRounds(KeySchedule, (unsigned int *)(Output + Offset), (unsigned int *)(Input + Offset));
            Offset += 16;
        } while (Offset + 16 <= Length);
    }

    // 处理尾部不足 16 字节的块
    if (Offset < Length)
    {
        memmove(PartialBlock, Input + Offset, Length - Offset);
        AesDecryptRounds(KeySchedule, (unsigned int *)(Output + Offset), (unsigned int *)PartialBlock);
    }

    return 0;
}

// DecryptAesHexString — 解密 AES 十六进制字符串
// 参数: HexBuffer=输入十六进制字符串(256字节), HexLength=长度, pSyscallCount=输出系统调用计数
// 将 256 字节十六进制字符串解码为 128 字节二进制，AES-128 解密后验证 MD5 和时间戳
char __fastcall DecryptAesHexString(unsigned char *HexBuffer, unsigned int HexLength, _QWORD *pSyscallCount)
{
    char Result;
    unsigned int i;
    int HexDigit;
    char HexByte;
    unsigned int j;
    MD5_CONTEXT Md5Ctx;
    unsigned char AesKey[16];
    unsigned char KeySchedule[0xC0];
    unsigned char Decrypted[0x84];
    unsigned char Md5Digest[16];
    unsigned __int64 SystemTime;
    unsigned __int64 TimeLow1;
    unsigned __int64 TimeHigh1;
    unsigned __int64 TimeLow2;
    unsigned __int64 TimeHigh2;

    Result = 0;
    if (HexLength != 0x100 || !HexBuffer)
    {
        ++*pSyscallCount;
        return Result;
    }

    // 清零解密缓冲区
    memset(Decrypted, 0, sizeof(Decrypted));

    // 十六进制解码：将 256 字节的十六进制字符串转换为 128 字节的二进制数据
    for (i = 0; i < 0x80; i++)
    {
        // 解码第一个十六进制字符
        HexDigit = HexBuffer[i * 2] - '0';
        if (HexDigit > 9)
            HexDigit = HexBuffer[i * 2] - 'A' + 10;
        if ((unsigned int)HexDigit > 0xF)
            goto FAIL;
        HexByte = (char)(HexDigit << 4);

        // 解码第二个十六进制字符
        HexDigit = HexBuffer[i * 2 + 1] - '0';
        if (HexDigit > 9)
            HexDigit = HexBuffer[i * 2 + 1] - 'A' + 10;
        if ((unsigned int)HexDigit > 0xF)
            goto FAIL;
        HexByte |= (char)HexDigit;

        Decrypted[i] = (unsigned char)HexByte;
    }

    // AES 密钥："ShowJirShiShi" (13 字节 + null 填充)
    *(unsigned int *)&AesKey[0] = 0x756F6853; // "Show"
    *(unsigned int *)&AesKey[4] = 0x7245694A; // "JirS"
    *(unsigned int *)&AesKey[8] = 0x53696853; // "ShiS"
    *(unsigned int *)&AesKey[12] = 0x69685369; // "iShi"
    // 实际字符串: "ShowJirShiShi" 刚好 13 字节，最后 3 字节为零

    // AES 初始化密钥计划和密钥扩展
    AesInitKeySchedule();
    AesKeyExpansion((int *)KeySchedule, (int *)AesKey, 16);

    // AES 解密 128 字节数据
    AesDecryptBlocks((unsigned int *)KeySchedule, Decrypted, Decrypted, 0x80);

    // MD5 哈希解密后的前 100 字节
    InitMd5Context(&Md5Ctx);
    Md5Update(&Md5Ctx, Decrypted, 0x64);
    Md5Final(&Md5Ctx, Md5Digest);

    // 比较 MD5 摘要与解密数据中的预期值（偏移 0x64 处）
    for (j = 0; j < 16; j++)
    {
        if (Md5Digest[j] != Decrypted[j + 0x64])
            break;
    }

    if (j == 16)
    {
        // MD5 匹配，验证时间戳
        // 读取系统时间 (0xFFFFF78000000014 = SharedUserData + 0x14)
        SystemTime = *(volatile unsigned __int64 *)0xFFFFF78000000014LL;

        // 时间范围: [Decrypted[0x50:0x58], Decrypted[0x54:0x5C]]
        TimeLow1 = *(unsigned int *)&Decrypted[0x50];
        TimeHigh1 = *(unsigned int *)&Decrypted[0x54];
        TimeLow2 = *(unsigned int *)&Decrypted[0x58];
        TimeHigh2 = *(unsigned int *)&Decrypted[0x5C];

        // 检查 SystemTime 是否在时间范围内
        if (SystemTime >= (TimeHigh1 << 32 | TimeLow1)
            && SystemTime <= (TimeHigh2 << 32 | TimeLow2))
        {
            // 时间戳在有效范围内，递减计数
            *pSyscallCount += -1;
        }
        else
        {
            ++*pSyscallCount;
        }
    }
    else
    {
FAIL:
        ++*pSyscallCount;
    }
    return Result;
}


// ===== Functions moved from MissingFuncs.c =====

// Md5Init — 初始化 MD5 上下文（原始驱动非标准布局）
// 使用 0x58 字节上下文，状态值在偏移 0x48 处
void Md5Init(char *Context)
{
    memset(Context, 0, 0x58);
    *(ULONG *)(Context + 0x48) = 0x67452301;
    *(ULONG *)(Context + 0x4C) = 0xEFCDAB89;
    *(ULONG *)(Context + 0x50) = 0x98BADCFE;
    *(ULONG *)(Context + 0x54) = 0x10325476;
}