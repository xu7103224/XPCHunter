/* ============================================================================
 * core.c —— SDK 核心层：会话管理、协议封装、错误映射
 *
 * 这一层把与驱动的通信细节完全封装起来。上层 API 只关心业务语义。
 * ==========================================================================*/
#include "XpchSdk_internal.h"
#include <stdio.h>

/* ============================================================
 * MD5（只用于请求校验和，不用于安全用途）
 * ============================================================*/
typedef struct _MD5_CTX {
    ULONG State[4];
    ULONG Count[2];
    BYTE  Buffer[64];
} MD5_CTX;

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define F1(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define F2(x,y,z) (F1(z,x,y))
#define F3(x,y,z) ((x) ^ (y) ^ (z))
#define F4(x,y,z) ((y) ^ ((x) | ~(z)))
#define STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); \
    (a) = ROTL((a), (s)); \
    (a) += (b);

static void Md5Transform(ULONG State[4], const BYTE Block[64])
{
    ULONG a, b, c, d;
    ULONG x[16];
    int i;

    for (i = 0; i < 16; i++)
        x[i] = (ULONG)Block[i * 4]
             | ((ULONG)Block[i * 4 + 1] << 8)
             | ((ULONG)Block[i * 4 + 2] << 16)
             | ((ULONG)Block[i * 4 + 3] << 24);

    a = State[0]; b = State[1]; c = State[2]; d = State[3];

    STEP(F1, a, b, c, d, x[ 0], 0xD76AA478,  7)
    STEP(F1, d, a, b, c, x[ 1], 0xE8C7B756, 12)
    STEP(F1, c, d, a, b, x[ 2], 0x242070DB, 17)
    STEP(F1, b, c, d, a, x[ 3], 0xC1BDCEEE, 22)
    STEP(F1, a, b, c, d, x[ 4], 0xF57C0FAF,  7)
    STEP(F1, d, a, b, c, x[ 5], 0x4787C62A, 12)
    STEP(F1, c, d, a, b, x[ 6], 0xA8304613, 17)
    STEP(F1, b, c, d, a, x[ 7], 0xFD469501, 22)
    STEP(F1, a, b, c, d, x[ 8], 0x698098D8,  7)
    STEP(F1, d, a, b, c, x[ 9], 0x8B44F7AF, 12)
    STEP(F1, c, d, a, b, x[10], 0xFFFF5BB1, 17)
    STEP(F1, b, c, d, a, x[11], 0x895CD7BE, 22)
    STEP(F1, a, b, c, d, x[12], 0x6B901122,  7)
    STEP(F1, d, a, b, c, x[13], 0xFD987193, 12)
    STEP(F1, c, d, a, b, x[14], 0xA679438E, 17)
    STEP(F1, b, c, d, a, x[15], 0x49B40821, 22)

    STEP(F2, a, b, c, d, x[ 1], 0xF61E2562,  5)
    STEP(F2, d, a, b, c, x[ 6], 0xC040B340,  9)
    STEP(F2, c, d, a, b, x[11], 0x265E5A51, 14)
    STEP(F2, b, c, d, a, x[ 0], 0xE9B6C7AA, 20)
    STEP(F2, a, b, c, d, x[ 5], 0xD62F105D,  5)
    STEP(F2, d, a, b, c, x[10], 0x02441453,  9)
    STEP(F2, c, d, a, b, x[15], 0xD8A1E681, 14)
    STEP(F2, b, c, d, a, x[ 4], 0xE7D3FBC8, 20)
    STEP(F2, a, b, c, d, x[ 9], 0x21E1CDE6,  5)
    STEP(F2, d, a, b, c, x[14], 0xC33707D6,  9)
    STEP(F2, c, d, a, b, x[ 3], 0xF4D50D87, 14)
    STEP(F2, b, c, d, a, x[ 8], 0x455A14ED, 20)
    STEP(F2, a, b, c, d, x[13], 0xA9E3E905,  5)
    STEP(F2, d, a, b, c, x[ 2], 0xFCEFA3F8,  9)
    STEP(F2, c, d, a, b, x[ 7], 0x676F02D9, 14)
    STEP(F2, b, c, d, a, x[12], 0x8D2A4C8A, 20)

    STEP(F3, a, b, c, d, x[ 5], 0xFFFA3942,  4)
    /* 【族 2】驱动分派器校验请求校验和用的是 Md5Transform2，
       其 K[33] 是原版笔误值 0x8771F683（不是标准 0x8771F681）。
       用标准值会让每个请求都被判校验和不符而拒绝。 */
    STEP(F3, d, a, b, c, x[ 8], 0x8771F683, 11)
    STEP(F3, c, d, a, b, x[11], 0x6D9D6122, 16)
    STEP(F3, b, c, d, a, x[14], 0xFDE5380C, 23)
    STEP(F3, a, b, c, d, x[ 1], 0xA4BEEA44,  4)
    STEP(F3, d, a, b, c, x[ 4], 0x4BDECFA9, 11)
    STEP(F3, c, d, a, b, x[ 7], 0xF6BB4B60, 16)
    STEP(F3, b, c, d, a, x[10], 0xBEBFBC70, 23)
    STEP(F3, a, b, c, d, x[13], 0x289B7EC6,  4)
    STEP(F3, d, a, b, c, x[ 0], 0xEAA127FA, 11)
    STEP(F3, c, d, a, b, x[ 3], 0xD4EF3085, 16)
    STEP(F3, b, c, d, a, x[ 6], 0x04881D05, 23)
    STEP(F3, a, b, c, d, x[ 9], 0xD9D4D039,  4)
    STEP(F3, d, a, b, c, x[12], 0xE6DB99E5, 11)
    STEP(F3, c, d, a, b, x[15], 0x1FA27CF8, 16)
    STEP(F3, b, c, d, a, x[ 2], 0xC4AC5665, 23)

    STEP(F4, a, b, c, d, x[ 0], 0xF4292244,  6)
    STEP(F4, d, a, b, c, x[ 7], 0x432AFF97, 10)
    STEP(F4, c, d, a, b, x[14], 0xAB9423A7, 15)
    STEP(F4, b, c, d, a, x[ 5], 0xFC93A039, 21)
    STEP(F4, a, b, c, d, x[12], 0x655B59C3,  6)
    STEP(F4, d, a, b, c, x[ 3], 0x8F0CCC92, 10)
    STEP(F4, c, d, a, b, x[10], 0xFFEFF47D, 15)
    STEP(F4, b, c, d, a, x[ 1], 0x85845DD1, 21)
    STEP(F4, a, b, c, d, x[ 8], 0x6FA87E4F,  6)
    STEP(F4, d, a, b, c, x[15], 0xFE2CE6E0, 10)
    STEP(F4, c, d, a, b, x[ 6], 0xA3014314, 15)
    STEP(F4, b, c, d, a, x[13], 0x4E0811A1, 21)
    STEP(F4, a, b, c, d, x[ 4], 0xF7537E82,  6)
    STEP(F4, d, a, b, c, x[11], 0xBD3AF235, 10)
    STEP(F4, c, d, a, b, x[ 2], 0x2AD7D2BB, 15)
    STEP(F4, b, c, d, a, x[ 9], 0xEB86D391, 21)

    State[0] += a; State[1] += b; State[2] += c; State[3] += d;
    SecureZeroMemory(x, sizeof(x));
}

static void Md5Init(MD5_CTX *Ctx)
{
    Ctx->Count[0] = Ctx->Count[1] = 0;
    Ctx->State[0] = 0x67452301;
    Ctx->State[1] = 0xEFCDAB89;
    Ctx->State[2] = 0x98BADCFE;
    Ctx->State[3] = 0x10325476;
}

static void Md5Update(MD5_CTX *Ctx, const BYTE *Input, ULONG Len)
{
    ULONG i, index, partLen;

    index = (Ctx->Count[0] >> 3) & 0x3F;
    if ((Ctx->Count[0] += Len << 3) < (Len << 3))
        Ctx->Count[1]++;
    Ctx->Count[1] += Len >> 29;

    partLen = 64 - index;
    if (Len >= partLen) {
        memcpy(&Ctx->Buffer[index], Input, partLen);
        Md5Transform(Ctx->State, Ctx->Buffer);
        for (i = partLen; i + 63 < Len; i += 64)
            Md5Transform(Ctx->State, &Input[i]);
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&Ctx->Buffer[index], &Input[i], Len - i);
}

static void Md5Final(MD5_CTX *Ctx, BYTE Digest[16])
{
    static const BYTE Padding[64] = { 0x80 };
    BYTE bits[8];
    ULONG i, index, padLen;

    for (i = 0; i < 4; i++) {
        bits[i]     = (BYTE)(Ctx->Count[0] >> (i * 8));
        bits[i + 4] = (BYTE)(Ctx->Count[1] >> (i * 8));
    }
    index = (Ctx->Count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);
    Md5Update(Ctx, Padding, padLen);
    Md5Update(Ctx, bits, 8);

    for (i = 0; i < 16; i++)
        Digest[i] = (BYTE)(Ctx->State[i >> 2] >> ((i & 3) * 8));
    SecureZeroMemory(Ctx, sizeof(*Ctx));
}

/* ============================================================
 * 参数派生（设备名 → ioctl + keyByte）
 * ============================================================*/
BOOL XpchDeriveParams(const WCHAR *Name, PULONG IoControlCode, PUCHAR KeyByte)
{
    WCHAR Dest[64];
    UCHAR *Bytes;
    ULONG n, i, edi, first;
    UCHAR key;

    if (!Name || !IoControlCode || !KeyByte)
        return FALSE;

    /* "\\.\" + Name */
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

    edi = 0x20;
    for (i = 0; i < n - 4; i++) {
        ULONG w = (ULONG)Bytes[8 + i * 2] | ((ULONG)Bytes[9 + i * 2] << 8);
        edi = (w ^ ((w + edi) & 0xFFFFFFFF)) & 0xFFFFFFFF;
    }
    first = Bytes[8];
    *IoControlCode = (4 * (first | ((edi << 14) & 0xFFFFFFFF))) & 0xFFFFFFFF;

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

void XpchCryptBuffer(PUCHAR Buffer, ULONG Size, UCHAR KeyByte)
{
    ULONG i;
    for (i = 0; i < Size; i++)
        Buffer[i] = (UCHAR)~(Buffer[i] ^ KeyByte);
}

/* ============================================================
 * 内存
 * ============================================================*/
void *XpchAlloc(SIZE_T Bytes)
{
    if (!Bytes)
        Bytes = 1;
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Bytes);
}

void XpchFreeInternal(void *Memory)
{
    if (Memory)
        HeapFree(GetProcessHeap(), 0, Memory);
}

void XpchFree(void *Memory)
{
    XpchFreeInternal(Memory);
}

/* ============================================================
 * 命令调用
 * ============================================================*/
XPCH_STATUS XpchInvokeRaw(XPCH_SESSION *Session, ULONG Command,
                          PVOID In, ULONG InSize,
                          PVOID Out, ULONG OutSize)
{
    XPCH_SESSION_IMPL *Impl;
    XPCH_REQUEST Req;
    BYTE Digest[16];
    MD5_CTX Md5;
    DWORD Returned = 0;
    BYTE ResultByte = 0;
    BOOL Status;

    if (!Session)
        return XPCH_E_INVALID_ARG;
    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened || !Impl->Device)
        return XPCH_E_NOT_OPENED;
    if (Command < XPCH_CMD_MIN || Command > XPCH_CMD_MAX)
        return XPCH_E_INVALID_ARG;

    ZeroMemory(&Req, sizeof(Req));
    Req.Magic         = XPCH_MAGIC;
    Req.Command       = Command;
    Req.ResultBytePtr = (ULONG64)(ULONG_PTR)&ResultByte;
    Req.InPtr         = (ULONG64)(ULONG_PTR)In;
    Req.OutPtr        = (ULONG64)(ULONG_PTR)Out;
    Req.InSize        = InSize;
    Req.OutSize       = OutSize;

    Md5Init(&Md5);
    Md5Update(&Md5, (const BYTE *)&Req, XPCH_CHECKSUM_OFFSET);
    Md5Final(&Md5, Digest);
    Req.Checksum = (ULONG)Digest[0]
                 | ((ULONG)Digest[1] << 8)
                 | ((ULONG)Digest[2] << 16)
                 | ((ULONG)Digest[3] << 24);

    XpchCryptBuffer((PUCHAR)&Req, XPCH_REQUEST_SIZE, Impl->KeyByte);

    Status = DeviceIoControl(Impl->Device, Impl->IoControlCode,
                             &Req, XPCH_REQUEST_SIZE,
                             &Req, XPCH_REQUEST_SIZE,
                             &Returned, NULL);
    if (!Status)
        return XPCH_E_IOCTL;

    /* 驱动恒返回 STATUS_SUCCESS，成败只能看结果字节 */
    return ResultByte ? XPCH_OK : XPCH_E_REJECTED;
}

/* ============================================================
 * 会话生命周期
 * ============================================================*/
/* 驱动初始化握手。
 *
 * 先发 0x22（唯一在驱动未就绪时放行的命令），入参必须是 0x100 字节的
 * 合法许可包、OutSize 必须正好 4；成功则驱动置 GT[0x304]=1。
 * 随后用 0x24 确认能真正取到构建号。 */
XPCH_STATUS XpchHandshake(XPCH_SESSION *Session)
{
    UCHAR Packet[0x100];
    ULONG SsdtOut = 0;
    ULONG Build = 0;

    if (!Session)
        return XPCH_E_INVALID_ARG;

    if (!XpchBuildLicensePacket(Packet))
        return XPCH_E_NOT_SUPPORTED;

    XpchInvokeRaw(Session, CMD_QUERY_PROCESS_INFO,
                  Packet, sizeof(Packet), &SsdtOut, sizeof(SsdtOut));

    /* 0x24 能返回非零构建号才算真正就绪 */
    if (XpchInvokeRaw(Session, CMD_GET_BUILD_NUMBER, NULL, 0,
                      &Build, sizeof(Build)) == XPCH_OK
        && Build != 0)
        return XPCH_OK;

    return XPCH_E_HANDSHAKE;
}

XPCH_STATUS XpchOpen(XPCH_SESSION *Session)
{
    XPCH_SESSION_IMPL *Impl;
    HANDLE Device;
    ULONG IoctlCode = 0;
    UCHAR KeyByte = 0;
    XPCH_STATUS St;

    if (!Session)
        return XPCH_E_INVALID_ARG;

    ZeroMemory(Session, sizeof(*Session));
    Impl = XPCH_IMPL(Session);

    /* 派生参数：失败说明设备名不可用，但先打开设备再判定更准确 */
    if (!XpchDeriveParams(L"View++ByLinxer", &IoctlCode, &KeyByte))
        return XPCH_E_INVALID_ARG;

    Device = CreateFileW(XPCH_DEVICE_NAME,
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (Device == INVALID_HANDLE_VALUE)
        return XPCH_E_NO_DEVICE;

    Impl->Device = Device;
    Impl->IoControlCode = IoctlCode;
    Impl->KeyByte = KeyByte;
    Impl->Opened = TRUE;

    /* 握手：驱动 GT[0x304] 为 0 时只放行 0x22，其余命令全被拒。
       0x22 要求 0x100 字节合法许可包 + OutSize==4，验证通过后驱动才就绪。
       之后用 0x24 确认真正可以取数据。 */
    St = XpchHandshake(Session);
    if (St != XPCH_OK) {
        XpchClose(Session);
        return St;
    }

    return XPCH_OK;
}

void XpchClose(XPCH_SESSION *Session)
{
    XPCH_SESSION_IMPL *Impl;

    if (!Session)
        return;
    Impl = XPCH_IMPL(Session);
    if (Impl->Opened && Impl->Device && Impl->Device != INVALID_HANDLE_VALUE)
        CloseHandle(Impl->Device);
    SecureZeroMemory(Session, sizeof(*Session));
}

XPCH_STATUS XpchProbe(void)
{
    XPCH_SESSION Session;
    XPCH_STATUS St = XpchOpen(&Session);
    if (St == XPCH_OK)
        XpchClose(&Session);
    return St;
}

XPCH_STATUS XpchGetBuildNumber(XPCH_SESSION *Session, ULONG *BuildNumber)
{
    XPCH_SESSION_IMPL *Impl;
    XPCH_STATUS St;

    if (!Session || !BuildNumber)
        return XPCH_E_INVALID_ARG;
    Impl = XPCH_IMPL(Session);
    if (!Impl->Opened)
        return XPCH_E_NOT_OPENED;

    St = XpchInvokeRaw(Session, CMD_GET_BUILD_NUMBER, NULL, 0,
                       BuildNumber, sizeof(*BuildNumber));
    return St;
}

/* ============================================================
 * 状态码 → 文本
 * ============================================================*/
const WCHAR *XpchStatusText(XPCH_STATUS Status)
{
    switch (Status) {
    case XPCH_OK:                  return L"成功";
    case XPCH_E_NO_DEVICE:         return L"无法打开驱动设备（驱动未加载或权限不足）";
    case XPCH_E_NOT_OPENED:        return L"会话未打开";
    case XPCH_E_HANDSHAKE:         return L"握手失败（驱动未就绪或版本不匹配）";
    case XPCH_E_IOCTL:             return L"DeviceIoControl 调用失败";
    case XPCH_E_REJECTED:          return L"驱动拒绝了请求";
    case XPCH_E_INVALID_ARG:       return L"参数非法";
    case XPCH_E_NOT_FOUND:         return L"未找到目标";
    case XPCH_E_ACCESS_DENIED:     return L"无访问权限";
    case XPCH_E_BUFFER_TOO_SMALL:  return L"缓冲区不足";
    case XPCH_E_NO_DATA:           return L"驱动返回空数据";
    case XPCH_E_BAD_RESPONSE:      return L"驱动输出结构异常";
    case XPCH_E_NO_MEMORY:         return L"内存不足";
    case XPCH_E_NOT_SUPPORTED:     return L"当前版本不支持";
    case XPCH_E_PARTIAL:           return L"部分成功";
    default:                       return L"未知错误";
    }
}

/* ============================================================
 * 工具
 * ============================================================*/
BOOL XpchUtf16ToAnsi(const WCHAR *Wide, char *Ansi, ULONG AnsiChars)
{
    int n;
    if (!Wide || !Ansi || !AnsiChars)
        return FALSE;
    n = WideCharToMultiByte(CP_ACP, 0, Wide, -1, Ansi, (int)AnsiChars, NULL, NULL);
    if (n <= 0) {
        Ansi[0] = 0;
        return FALSE;
    }
    return TRUE;
}