// ============================================================================
// XPCHunterUM — 用户态客户端与内核驱动的通信协议
//
// 两侧交叉验证的结论（详见 docs/reversing/用户态内核通信协议.md）：
//   原始用户态 sub_14004DD40 由设备名派生出 ioctl 与 keyByte；
//   原始驱动 DispatchDeviceControl 用同一对值做校验与解密。
//   实测 Name=L"View++ByLinxer" → ioctl=0x05E00158、key=0xCF，
//   与驱动 GT[0x1E0]/GT[0x1E1] 完全一致。
//
// 请求结构（0x30 字节，全部字段在加密前填写）：
//     0x00  DWORD  Magic         = 0x20240810
//     0x04  DWORD  Command       命令号 [0x20, 0x13A]
//     0x08  QWORD  OutputBuffer
//     0x10  QWORD  ContextPointer
//     0x18  QWORD  ExtraPointer
//     0x20  DWORD  OutputSize
//     0x24  DWORD  ContextSize
//     0x28  DWORD  Checksum      = MD5(明文前 0x28 字节)[0..3]
// ============================================================================
#ifndef XPCHUNTER_UM_H
#define XPCHUNTER_UM_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 设备名前缀与后缀：\\.\<Suffix>。驱动用 IoCreateSymbolicLink 创建同名链接，
   而原始用户态是从驱动文件名去掉 .sys 派生，故两者必须一致。 */
#define XPCH_DEVICE_PREFIX      L"\\\\.\\"
#define XPCH_DEVICE_SUFFIX      L"View++ByLinxer"
#define XPCH_DEVICE_NAME        XPCH_DEVICE_PREFIX XPCH_DEVICE_SUFFIX

#define XPCH_MAGIC              0x20240810u
#define XPCH_REQUEST_SIZE       0x30u
#define XPCH_CHECKSUM_OFFSET    0x28u
#define XPCH_CMD_MIN            0x20u
#define XPCH_CMD_MAX            0x13Au

/* 请求头，与内核 DispatchDeviceControl 的解析布局一一对应 */
#pragma pack(push, 1)
typedef struct _XPCH_REQUEST {
    ULONG   Magic;              /* +0x00 */
    ULONG   Command;            /* +0x04 */
    ULONG64 OutputBuffer;       /* +0x08 */
    ULONG64 ContextPointer;     /* +0x10 */
    ULONG64 ExtraPointer;       /* +0x18 */
    ULONG   OutputSize;         /* +0x20 */
    ULONG   ContextSize;        /* +0x24 */
    ULONG   Checksum;           /* +0x28 */
    ULONG   Reserved;           /* +0x2C */
} XPCH_REQUEST;
#pragma pack(pop)

/* 常用命令号（= 0x20 + 命令表下标） */
#define XPCH_CMD_READ_PROCESS_MEMORY        0x20u
#define XPCH_CMD_RESET_PROCESS_CONTEXT      0x21u
#define XPCH_CMD_QUERY_PROCESS_INFO         0x22u   /* 唯一无需初始化的命令 */
#define XPCH_CMD_GET_MODULE_COUNT           0x24u
#define XPCH_CMD_ENUM_KERNEL_DRIVERS        0x25u
#define XPCH_CMD_ENUM_THREADS               0x2Au
#define XPCH_CMD_ENUM_KERNEL_MODULES        0x3Cu
#define XPCH_CMD_THREAD_OPERATION           0x3Du
#define XPCH_CMD_THREAD_MONITOR             0x3Eu

typedef struct _XPCH_CLIENT {
    HANDLE          Device;
    ULONG           IoControlCode;  /* 由设备名派生，= 驱动 GT[0x1E0] */
    UCHAR           KeyByte;        /* 由设备名派生，= 驱动 GT[0x1E1] */
    BOOL            Opened;
} XPCH_CLIENT, *PXPCH_CLIENT;

/* 打开/关闭设备（打开时自动派生 ioctl 与 keyByte） */
BOOL XpchOpen(PXPCH_CLIENT Client);
void XpchClose(PXPCH_CLIENT Client);

/* 由设备名（不含 "\\.\"）派生 ioctl 与 keyByte，等价于两侧的密钥算法 */
BOOL XpchDeriveParams(const WCHAR *Name, PULONG IoControlCode, PUCHAR KeyByte);

/* 对 0x30 字节缓冲做加密/解密（自反：~(x ^ key)） */
void XpchCryptBuffer(PUCHAR Buffer, ULONG Size, UCHAR KeyByte);

/*
 * 发送一次命令。
 *   Command     : 命令号
 *   Output      : 用户态输出缓冲（可为 NULL）
 *   OutputSize  : 输出缓冲大小
 *   Context     : 上下文指针（可为 NULL）
 *   ContextSize : 上下文大小
 *   Extra       : 附加指针（可为 NULL）
 * 返回内核 Handler 的返回值；通信失败返回 FALSE 并设置 LastError。
 */
BOOL XpchInvoke(PXPCH_CLIENT Client,
                ULONG Command,
                PVOID Output, ULONG OutputSize,
                PVOID Context, ULONG ContextSize,
                PVOID Extra);

/* 握手：0x22 探测 → 0x21 复位上下文 → 0x24 读构建号验证链路 */
BOOL XpchHandshake(PXPCH_CLIENT Client);

#ifdef __cplusplus
}
#endif

#endif /* XPCHUNTER_UM_H */