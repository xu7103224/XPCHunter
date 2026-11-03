/* ============================================================================
 * XpchSdk_internal.h —— SDK 内部定义，不对外发布
 *
 * 与驱动的通信协议（0x30 字节请求、加密、MD5 校验）在 core.c 里实现。
 * 这些细节对 SDK 使用者完全隐藏。
 * ==========================================================================*/
#ifndef XPCHSDK_INTERNAL_H
#define XPCHSDK_INTERNAL_H

#include <windows.h>
#include "XpchSdk.h"

/* ---- 通信协议常量（与驱动 xpc_ioctl.h 一致）---- */
#define XPCH_DEVICE_NAME        L"\\\\.\\View++ByLinxer"
#define XPCH_MAGIC              0x20240810u
#define XPCH_REQUEST_SIZE       0x30u
#define XPCH_CHECKSUM_OFFSET    0x28u
#define XPCH_CMD_MIN            0x20u
#define XPCH_CMD_MAX            0x13Au

#pragma pack(push, 1)
typedef struct _XPCH_REQUEST {
    ULONG   Magic;              /* +0x00 */
    ULONG   Command;            /* +0x04 */
    ULONG64 ResultBytePtr;      /* +0x08 驱动写回 1 字节结果码 */
    ULONG64 InPtr;              /* +0x10 输入缓冲 */
    ULONG64 OutPtr;             /* +0x18 输出缓冲 */
    ULONG   InSize;             /* +0x20 */
    ULONG   OutSize;            /* +0x24 */
    ULONG   Checksum;           /* +0x28 */
    ULONG   Reserved;           /* +0x2C */
} XPCH_REQUEST;
#pragma pack(pop)

/* ---- 会话内部结构（与 XpchSdk.h 里 256 字节 Reserved 对应）---- */
typedef struct _XPCH_SESSION_IMPL {
    HANDLE  Device;
    ULONG   IoControlCode;
    UCHAR   KeyByte;
    BOOL    Opened;
    ULONG   Build;              /* 缓存驱动报告的构建号 */
} XPCH_SESSION_IMPL;

C_ASSERT(sizeof(XPCH_SESSION_IMPL) <= XPCH_SESSION_PRIVATE_SIZE);

#define XPCH_IMPL(S) ((XPCH_SESSION_IMPL *)(S)->Reserved)

/* ---- 命令号（只读能力用到的）---- */
#define CMD_QUERY_PROCESS_INFO      0x22u   /* 握手专用（驱动未就绪时唯一放行） */
#define CMD_GET_BUILD_NUMBER        0x24u
#define CMD_CHECK_PROCESS_ACCESS    0x27u
#define CMD_QUERY_PROCESS_PATH      0x2Au   /* 实为进程路径查询 */
#define CMD_ENUM_SYSTEM_HANDLES     0x26u
#define CMD_ENUM_PROCESS_WIN10      0xE4u
#define CMD_ENUM_HOOK_INFO          0x117u

/* ---- SDK 扩展命令（占用原版显式空槽，见驱动 XpchExtensions.c）----
 * 原 0x09A/0x09B（进程线程/模块枚举）已改为 SDK 侧经 0x099/0x023
 * 逐次安全读遍历（见 process.c）。
 * 2026-11-03：0x09A/0x09B 槽位重新启用为新命令：
 *   0x09A Token 特权调整（提权/降权/查询）
 *   0x09B 进程原语（分配/释放/改保护/远程线程，注入映射用） */
#define CMD_X_READ_PROC_MEM         0x023u  /* {pid,addr,size} -> {copied,data} */
#define CMD_X_WRITE_PROC_MEM        0x081u  /* {pid,addr,size,data} */
#define CMD_X_WRITE_KERNEL_MEM      0x082u  /* {addr,size,data} MDL 写 */
#define CMD_X_READ_KERNEL_MEM       0x099u  /* {addr,size} -> {copied,data} */
#define CMD_X_ADJUST_TOKEN          0x09Au  /* {pid,mode} -> {count,enabled} */
#define CMD_X_PROCESS_OP            0x09Bu  /* {pid,op,a1,a2,a3} -> {value} */
#define CMD_X_ENUM_KERNEL_MODULES   0x0C5u  /* {} -> 内核模块数组(DriverSection) */

/* ---- 内部工具 ---- */
BOOL  XpchDeriveParams(const WCHAR *Name, PULONG IoControlCode, PUCHAR KeyByte);
void  XpchCryptBuffer(PUCHAR Buffer, ULONG Size, UCHAR KeyByte);

/* 发一条命令。
 * 返回 XPCH_OK / XPCH_E_IOCTL / XPCH_E_REJECTED。 */
XPCH_STATUS XpchInvokeRaw(XPCH_SESSION *Session, ULONG Command,
                          PVOID In, ULONG InSize,
                          PVOID Out, ULONG OutSize);

/* 驱动初始化握手（失败返回 XPCH_E_HANDSHAKE） */
XPCH_STATUS XpchHandshake(XPCH_SESSION *Session);

/* 构造 0x22 用的合法许可包（0x100 字节大写十六进制）。
   握手必须用它，否则驱动不就绪、其余命令全被拒。 */
BOOL XpchBuildLicensePacket(UCHAR OutHex[0x100]);
void XpchAes128EncryptBlock(const UCHAR Key[16], const UCHAR In[16],
                            UCHAR Out[16]);

/* 分配/释放（统一用进程堆，XpchFree 对应） */
void *XpchAlloc(SIZE_T Bytes);
void  XpchFreeInternal(void *Memory);

#endif /* XPCHSDK_INTERNAL_H */