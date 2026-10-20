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
//
// 【2026-10-20 修正字段语义】早期按"Output/Context/Extra"命名，是错的。
// 原始处理器统一签名为
//     char Handler(PVOID In, ULONG InSize, PVOID Out, ULONG OutSize)
// 分派器（0x1400825AB..5BA）的寄存器映射为
//     rcx = [buf+0x10]   → In
//     edx = [buf+0x20]   → InSize
//     r8  = [buf+0x18]   → Out
//     r9d = [buf+0x24]   → OutSize
// 交叉验证：
//   CmdGetModuleCount(in=?, inSize, out=DWORD*, outSize)
//       → 要求 out != NULL 且 outSize == 4，把构建号写到 out
//   CmdEnumThreads(PID*, 8, WCHAR[260], 520)
//       → 要求 inSize == 8 && outSize == 520，读 *PID，写 0x208 字节路径
//   CmdReadProcessMemory(ULONG64 *Addr, 8)
//       → 要求 inSize == 8，只读 *Addr
// 也就是说 **+0x08 不是数据缓冲**，它只是驱动写回 1 字节结果码的位置。
//
//     0x00  DWORD  Magic         = 0x20240810
//     0x04  DWORD  Command       命令号 [0x20, 0x13A]
//     0x08  QWORD  ResultBytePtr 驱动写回 1 字节结果（1=成功）
//     0x10  QWORD  InPtr         命令输入缓冲
//     0x18  QWORD  OutPtr        命令输出缓冲
//     0x20  DWORD  InSize        输入长度
//     0x24  DWORD  OutSize       输出长度
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
    ULONG64 ResultBytePtr;      /* +0x08 驱动写回 1 字节结果码 */
    ULONG64 InPtr;              /* +0x10 输入缓冲 */
    ULONG64 OutPtr;             /* +0x18 输出缓冲 */
    ULONG   InSize;             /* +0x20 */
    ULONG   OutSize;            /* +0x24 */
    ULONG   Checksum;           /* +0x28 */
    ULONG   Reserved;           /* +0x2C */
} XPCH_REQUEST;
#pragma pack(pop)

/* 常用命令号（= 0x20 + 命令表下标）
 *
 * 名称与参数形状均取自原命令表 InitCommandHandlerTable (0x1400815B0)：
 *   idx  = Command - 0x20，槽位 = GT[0x921 + idx] */
#define XPCH_CMD_READ_PROCESS_MEMORY        0x20u  /* CmdReadProcessMemory      in: ULONG64 addr[1], inSize=8                    */
#define XPCH_CMD_RESET_PROCESS_CONTEXT      0x21u  /* CmdResetProcessContext                                            */
#define XPCH_CMD_QUERY_PROCESS_INFO         0x22u  /* CmdQueryProcessInfo       唯一无需初始化的命令                      */
#define XPCH_CMD_GET_MODULE_COUNT           0x24u  /* CmdGetModuleCount         out: DWORD build#, outSize=4             */
#define XPCH_CMD_ENUM_KERNEL_DRIVERS        0x25u  /* CmdEnumKernelDrivers                                              */
#define XPCH_CMD_ENUM_HANDLES               0x26u  /* CmdEnumHandles                                                    */
#define XPCH_CMD_CHECK_PROCESS_ACCESS       0x27u  /* CmdCheckProcessAccess                                             */
#define XPCH_CMD_PROCESS_OPERATION          0x28u  /* CmdProcessOperation                                               */
#define XPCH_CMD_ENUM_THREADS               0x2Au  /* CmdEnumThreads            in: ULONG pid, inSize=8; out: WCHAR[260], outSize=520 */
#define XPCH_CMD_ENUM_KERNEL_MODULES        0x3Cu  /* CmdEnumKernelModules                                              */
#define XPCH_CMD_THREAD_OPERATION           0x3Du  /* CmdThreadOperation                                                */
#define XPCH_CMD_THREAD_MONITOR             0x3Eu  /* CmdThreadMonitor                                                  */
#define XPCH_CMD_STUB_ALWAYS_TRUE           0x7Fu  /* CmdStubAlwaysTrue         (0x95 槽)                               */

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
 *   Command : 命令号
 *   In      : 命令输入缓冲（可为 NULL）
 *   InSize  : 输入长度（处理器会校验，例如 8 或 4）
 *   Out     : 命令输出缓冲（可为 NULL）
 *   OutSize : 输出长度（处理器会校验，例如 4 / 520 / 0x1000）
 *   Result  : 可选；接收驱动写回的结果字节（1 = 处理器成功）
 * 返回 TRUE 表示结果字节非零，即处理器真正执行且返回成功。
 */
BOOL XpchInvoke(PXPCH_CLIENT Client,
                ULONG Command,
                PVOID In, ULONG InSize,
                PVOID Out, ULONG OutSize,
                PUCHAR Result);

/* 握手：只发 0x24，读回构建号验证整条链路 */
BOOL XpchHandshake(PXPCH_CLIENT Client);

/* ============================================================================
 * 进程列表（Process 页数据层）—— 见 src/ProcessList.c
 *
 *   0xE4 CmdEnumProcessListWin10：无入参，输出 N 个 0x298 字节条目
 *        （+0x00 EPROCESS、+0x108 PID、+0x290 是否有后继）
 *   0x2A CmdEnumThreads：名字是枚举线程，实际实现是进程映像路径查询
 *        （入 8 字节 PID，出 WCHAR[260] 路径）
 * ========================================================================== */
#define XPCH_CMD_ENUM_PROCESS_WIN10   0xE4u
#define XPCH_CMD_QUERY_PROCESS_PATH   0x2Au   /* 同 XPCH_CMD_ENUM_THREADS，实现是路径查询 */

#define FE_PROC_ENTRY_SIZE   0x298u
#define FE_PROC_PID_OFFSET   0x108u
#define FE_PROC_NEXT_OFFSET  0x290u
#define FE_PROC_NAME_OFFSET  0x08u   /* 驱动兜底枚举写入的 ImageFileName（16 字节 ANSI） */
#define FE_PROC_PATH_BYTES   520u
#define FE_PROC_PATH_CHARS   260u
#define FE_PROC_DEFAULT_MAX  512u
#define FE_PROC_HARD_MAX     1024u

typedef struct _FE_PROCESS {
    ULONG64 Eprocess;
    ULONG   Pid;
    char    Name[16];                     /* 条目 +0x08 = EPROCESS.ImageFileName */
    WCHAR   Path[FE_PROC_PATH_CHARS];     /* 0x2A 查询到的完整路径（暂未启用） */
} FE_PROCESS;

typedef struct _FE_PROCESS_LIST {
    ULONG       Count;
    ULONG       Capacity;
    FE_PROCESS *Items;
} FE_PROCESS_LIST;

BOOL FeLoadProcessList(XPCH_CLIENT *Client, ULONG MaxCount, FE_PROCESS_LIST *List);
void FeFreeProcessList(FE_PROCESS_LIST *List);
BOOL FeLoadProcessPath(XPCH_CLIENT *Client, ULONG Pid, WCHAR *Path, ULONG PathChars);
BOOL FeLoadProcessPathWin32(ULONG Pid, WCHAR *Path, ULONG PathChars);
void FeWideToAnsi(const WCHAR *Wide, char *Ansi, size_t AnsiChars);
BOOL FePrintProcessList(XPCH_CLIENT *Client);

#ifdef __cplusplus
}
#endif

#endif /* XPCHUNTER_UM_H */