/* ============================================================================
 * XpchSdk.h —— XPCHunter 内核只读能力 SDK（公开接口）
 *
 * 用途：为第三方项目提供通过 XPCHunterDrv 驱动获取内核信息的只读能力。
 *       不包含任何破坏性操作（不杀进程、不写内存、不卸载驱动）。
 *
 * 使用方式：
 *     1. 编译前 define XPCHSDK_STATIC（或直接链接 XpchSdk.lib）
 *     2. #include "XpchSdk.h"
 *     3. 链接 XpchSdk.lib + advapi32.lib + wintrust.lib + crypt32.lib + psapi.lib
 *
 * 典型流程：
 *     XPCH_SESSION s = {0};
 *     if (XpchOpen(&s) != XPCH_OK) return;
 *     XPCH_PROCESS_INFO *procs; ULONG n;
 *     if (XpchEnumProcesses(&s, &procs, &n) == XPCH_OK) {
 *         for (ULONG i = 0; i < n; i++) printf("%lu %s\n", procs[i].Pid, procs[i].Name);
 *         XpchFree(procs);
 *     }
 *     XpchClose(&s);
 *
 * 线程安全：每个 XPCH_SESSION 内部串行化（驱动侧也是全局串行的）。
 *           不同会话可以并行使用，但共用同一驱动时实际仍会排队。
 *
 * 字符集：所有字符串均为 UTF-16（WCHAR）。如只需 ANSI，用 XpchUtf16ToAnsi 转换。
 * ==========================================================================*/
#ifndef XPCHSDK_H
#define XPCHSDK_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 版本 ---- */
#define XPCHSDK_VERSION_MAJOR   1
#define XPCHSDK_VERSION_MINOR   0
#define XPCHSDK_VERSION_STRING  L"1.0.0"

/* ============================================================================
 * 错误码
 *
 * 所有 API 返回 XPCH_STATUS。XPCH_OK 为 0，其余为负值（便于 `if (st != XPCH_OK)`）。
 * ==========================================================================*/
typedef enum _XPCH_STATUS {
    XPCH_OK                     = 0,    /* 成功 */

    /* --- 会话/连接 --- */
    XPCH_E_NO_DEVICE            = -1,   /* 打不开 \\.\View++ByLinxer：驱动未加载或权限不足 */
    XPCH_E_NOT_OPENED           = -2,   /* 会话未打开就调用了需要连接的 API */
    XPCH_E_HANDSHAKE            = -3,   /* 握手失败：驱动未完成初始化或版本不匹配 */
    XPCH_E_IOCTL                = -4,   /* DeviceIoControl 本身失败（通常意味着 ioctl 码不匹配） */
    XPCH_E_REJECTED             = -5,   /* 驱动拒绝：结果字节为 0（见文档"10 个拒绝点"） */

    /* --- 参数 --- */
    XPCH_E_INVALID_ARG          = -6,   /* 入参为空/越界/长度非法 */
    XPCH_E_NOT_FOUND            = -7,   /* 目标进程/模块/条目不存在 */
    XPCH_E_ACCESS_DENIED        = -8,   /* 目标对象无访问权限（受保护进程等） */

    /* --- 数据 --- */
    XPCH_E_BUFFER_TOO_SMALL     = -9,   /* 调用方提供的缓冲区不足 */
    XPCH_E_NO_DATA              = -10,  /* 驱动返回空结果（表为空、无匹配项） */
    XPCH_E_BAD_RESPONSE         = -11,  /* 驱动输出结构不符合预期（版本差异/布局变化） */
    XPCH_E_NO_MEMORY            = -12,  /* 本地内存分配失败 */

    /* --- 能力 --- */
    XPCH_E_NOT_SUPPORTED        = -13,  /* 当前 Windows 版本/驱动版本不支持该能力 */
    XPCH_E_PARTIAL              = -14   /* 部分成功：已返回能取到的部分数据 */
} XPCH_STATUS;

/* 把状态码转成可读的静态字符串（不要 free） */
const WCHAR *XpchStatusText(XPCH_STATUS Status);

/* ============================================================================
 * 会话
 *
 * 不透明结构。调用方可以栈上分配，但必须用 XpchOpen 初始化、XpchClose 释放。
 * 字段对调用方不透明，不要直接读写。
 * ==========================================================================*/
#define XPCH_SESSION_PRIVATE_SIZE  256

typedef struct _XPCH_SESSION {
    /* 内部状态，不要访问 */
    BYTE    Reserved[XPCH_SESSION_PRIVATE_SIZE];
} XPCH_SESSION;

/* 打开会话并完成握手。
 *
 * 成功返回 XPCH_OK，失败返回具体错误码：
 *   XPCH_E_NO_DEVICE  驱动未加载 / 无权限
 *   XPCH_E_HANDSHAKE  驱动已加载但未就绪
 *
 * 行为：CreateFile → 派生 ioctl/keyByte → 发 0x22 探活。
 * 重复调用是安全的（会先关闭旧句柄）。 */
XPCH_STATUS XpchOpen(XPCH_SESSION *Session);

/* 关闭会话。传 NULL 安全。 */
void XpchClose(XPCH_SESSION *Session);

/* 探测驱动是否可用（不建立长期会话）。
 * 返回 XPCH_OK 表示驱动已加载且就绪。 */
XPCH_STATUS XpchProbe(void);

/* 取驱动报告的 Windows 构建号（如 18362）。
 * 这是驱动当前运行的系统版本，不是 SDK 编译时的版本。 */
XPCH_STATUS XpchGetBuildNumber(XPCH_SESSION *Session, ULONG *BuildNumber);

/* ============================================================================
 * 进程
 * ==========================================================================*/
#define XPCH_PROC_NAME_CHARS   16      /* ImageFileName，含结尾 0 */
#define XPCH_PROC_PATH_CHARS   520     /* 完整路径，含结尾 0 */

typedef struct _XPCH_PROCESS_INFO {
    ULONG   Pid;
    ULONG64 Eprocess;                       /* EPROCESS 内核地址（只读用途） */
    char    Name[XPCH_PROC_NAME_CHARS];     /* 映像名，如 "explorer.exe" */
} XPCH_PROCESS_INFO;

/* 枚举全部进程。
 *
 * 成功时 *Processes 指向内部分配的数组，*Count 为条目数。
 * 调用方用完必须 XpchFree(*Processes)。
 *
 * 注意：返回的是驱动视角的完整进程链表，包含仅内核可见的进程。
 *       条目名最长 15 字符（EPROCESS.ImageFileName 限制）。 */
XPCH_STATUS XpchEnumProcesses(XPCH_SESSION *Session,
                              XPCH_PROCESS_INFO **Processes,
                              ULONG *Count);

/* 查询单个进程的完整映像路径。
 *
 * Path 需为 XPCH_PROC_PATH_CHARS 字符的缓冲。
 * 对系统进程（PID 0/4）可能返回空路径，此时返回 XPCH_OK 但 Path 为空串。 */
XPCH_STATUS XpchGetProcessPath(XPCH_SESSION *Session, ULONG Pid,
                               WCHAR *Path, ULONG PathChars);

/* 【实验性，语义有限，不建议依赖】
 *
 * 底层是 0x27 CmdCheckProcessAccess，它在原版里不是"可访问性查询"，
 * 而是"能否对该进程解除保护"的前置判定，内部会调
 * ProcessOperationWithAttach（附加到目标、清保护标志、调页表）。
 * 对普通进程这条路径本就返回 0，所以本接口对绝大多数进程都会报
 * "不可访问"——那不代表你没有权限，而是这条命令不回答这个问题。
 *
 * 保留它是因为驱动行为如此，但**不建议依赖它判断可访问性**。
 * 判断"能不能操作某进程"请直接 OpenProcess 看返回值。 */
XPCH_STATUS XpchIsProcessAccessible(XPCH_SESSION *Session, ULONG Pid,
                                    BOOL *Accessible);

/* ============================================================================
 * 线程
 * ==========================================================================*/
typedef struct _XPCH_THREAD_INFO {
    ULONG   Tid;
    ULONG   OwnerPid;
    ULONG   BasePriority;
    ULONG   DeltaPriority;
    ULONG64 StartAddress;
    ULONG64 KernelStack;
    ULONG64 Teb;
} XPCH_THREAD_INFO;

/* 枚举指定进程的线程。结果需 XpchFree。 */
XPCH_STATUS XpchEnumThreads(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_THREAD_INFO **Threads, ULONG *Count);

/* ============================================================================
 * 模块（进程内已加载的 DLL/EXE）
 * ==========================================================================*/
#define XPCH_MOD_NAME_CHARS   64
#define XPCH_MOD_PATH_CHARS   520

typedef struct _XPCH_MODULE_INFO {
    ULONG64 Base;
    ULONG64 Size;
    WCHAR   Name[XPCH_MOD_NAME_CHARS];
    WCHAR   Path[XPCH_MOD_PATH_CHARS];
} XPCH_MODULE_INFO;

/* 枚举进程模块。结果需 XpchFree。
 * 数据源是 psapi（纯用户态），不需要驱动即可工作，但需要目标进程可访问。 */
XPCH_STATUS XpchEnumModules(ULONG Pid, XPCH_MODULE_INFO **Modules, ULONG *Count);

/* ============================================================================
 * 句柄
 * ==========================================================================*/
typedef struct _XPCH_HANDLE_INFO {
    ULONG   Pid;
    ULONG   HandleIndex;
    ULONG   ObjectTypeIndex;
    ULONG   GrantedAccess;
    ULONG64 Object;
    WCHAR   TypeName[64];
} XPCH_HANDLE_INFO;

/* 枚举全系统句柄表（数据量大，可能数千条）。结果需 XpchFree。 */
XPCH_STATUS XpchEnumSystemHandles(XPCH_SESSION *Session,
                                  XPCH_HANDLE_INFO **Handles, ULONG *Count);

/* ============================================================================
 * 内核模块与驱动
 * ==========================================================================*/
#define XPCH_KMOD_NAME_CHARS  64
#define XPCH_KMOD_PATH_CHARS  320

typedef struct _XPCH_KERNEL_MODULE {
    ULONG64 Base;
    ULONG64 Size;                        /* 由相邻基址差值推算，最后一项为 0 */
    char    Name[XPCH_KMOD_NAME_CHARS];
    char    Path[XPCH_KMOD_PATH_CHARS];
} XPCH_KERNEL_MODULE;

/* 枚举已加载的内核模块（ntoskrnl/hal/各 .sys）。
 * 数据源 psapi 的 EnumDeviceDrivers，纯用户态。结果需 XpchFree。 */
XPCH_STATUS XpchEnumKernelModules(XPCH_KERNEL_MODULE **Modules, ULONG *Count);

#define XPCH_DRV_NAME_CHARS  128
#define XPCH_DRV_DISP_CHARS  160
#define XPCH_DRV_PATH_CHARS  320

typedef struct _XPCH_DRIVER_INFO {
    char    Name[XPCH_DRV_NAME_CHARS];       /* 服务名 */
    char    Display[XPCH_DRV_DISP_CHARS];    /* 显示名 */
    char    Path[XPCH_DRV_PATH_CHARS];       /* ImagePath */
    DWORD   State;                           /* SERVICE_RUNNING 等 */
    DWORD   Start;                           /* SERVICE_BOOT_START 等 */
    DWORD   Type;                            /* SERVICE_KERNEL_DRIVER 等 */
} XPCH_DRIVER_INFO;

/* 枚举系统注册的内核驱动服务（SCM）。纯用户态，结果需 XpchFree。 */
XPCH_STATUS XpchEnumDrivers(XPCH_DRIVER_INFO **Drivers, ULONG *Count);

/* 找出"已加载但 SCM 里没有对应服务"的隐藏驱动。
 * 判定基于内核模块列表与驱动服务列表的差集，可能存在误报（如临时加载的驱动）。 */
XPCH_STATUS XpchEnumHiddenDrivers(XPCH_SESSION *Session,
                                  XPCH_KERNEL_MODULE **Hidden, ULONG *Count);

/* ============================================================================
 * SSDT / 系统调用表
 * ==========================================================================*/
#define XPCH_HOOK_DISASM_CHARS  96

typedef struct _XPCH_SSDT_ENTRY {
    ULONG   TableIndex;         /* 1 = SSDT，2 = Shadow SSDT */
    ULONG   Index;              /* 表内索引（syscall 号） */
    ULONG64 Current;            /* 当前地址 */
    ULONG64 Original;           /* 磁盘原始地址 */
    BOOL    AddressPatched;     /* 表项被改写（Current != Original） */
    BOOL    BytesPatched;       /* 函数前 16 字节被改（inline patch） */
    BYTE    OriginalBytes[16];  /* 磁盘原始指令 */
    char    Disasm[XPCH_HOOK_DISASM_CHARS];
} XPCH_SSDT_ENTRY;

/* 取两张系统调用表的全部条目及改写标志。
 *
 * 典型数量：Win10 18362 上 table1=454、table2=454、合计 908。
 * 结果需 XpchFree。
 *
 * 这是原版 "Ring0 Hooks" 页的数据源。检查是否有 hook 时，
 * 遍历结果找 AddressPatched 或 BytesPatched 为真的条目。 */
XPCH_STATUS XpchEnumSsdtHooks(XPCH_SESSION *Session,
                              XPCH_SSDT_ENTRY **Entries, ULONG *Count);

/* ============================================================================
 * Ring3 Hook（IAT 劫持 + inline patch）
 * ==========================================================================*/
typedef struct _XPCH_RING3_HOOK {
    WCHAR   Owner[64];          /* 发起调用的模块 */
    WCHAR   TargetModule[64];   /* 被指向的模块 */
    ULONG64 IatAddress;         /* IAT 表项地址 */
    ULONG64 Target;             /* 表项指向的地址 */
} XPCH_RING3_HOOK;

/* 扫描指定进程的 Ring3 钩子（IAT 劫持 + 主模块 inline patch）。
 *
 * 需要目标进程的 PROCESS_VM_READ 权限；受保护进程会返回 XPCH_E_ACCESS_DENIED。
 * 结果需 XpchFree。
 *
 * 耗时：单个进程通常 < 2 秒；模块多的进程（Chrome 等）可能更久。 */
XPCH_STATUS XpchScanProcessHooks(XPCH_SESSION *Session, ULONG Pid,
                                 XPCH_RING3_HOOK **Hooks, ULONG *Count);

/* ============================================================================
 * 签名校验
 * ==========================================================================*/
typedef enum _XPCH_SIGNATURE_STATE {
    XPCH_SIG_UNKNOWN    = 0,
    XPCH_SIG_VALID      = 1,    /* 有内嵌签名且信任链完整 */
    XPCH_SIG_INVALID    = 2,    /* 有签名但校验失败/证书过期 */
    XPCH_SIG_UNSIGNED   = 3     /* 无内嵌签名 */
} XPCH_SIGNATURE_STATE;

/* 校验文件的 Authenticode 签名。
 *
 * 只检查内嵌签名，不查系统 catalog —— 因此 system32 下部分只靠 catalog
 * 签名的 DLL 会被报成 UNSIGNED。这是已知限制，与原版行为一致。 */
XPCH_STATUS XpchVerifyFileSignature(const WCHAR *Path,
                                    XPCH_SIGNATURE_STATE *State);

/* ============================================================================
 * 内存读取
 * ==========================================================================*/
/* 读目标进程的内存（通过驱动，可读受保护进程）。
 *
 * 与 ReadProcessMemory 的区别：走驱动侧 KeStackAttachProcess，
 * 能读普通 API 读不到的进程。但目标进程被保护时仍可能失败。
 * 结果需 XpchFree。 */
XPCH_STATUS XpchReadProcessMemory(XPCH_SESSION *Session, ULONG Pid,
                                  ULONG64 Address, ULONG Size,
                                  BYTE **Buffer, ULONG *Read);

/* ============================================================================
 * 工具函数
 * ==========================================================================*/
/* 释放 SDK 分配的内存。所有返回指针的 API 都必须用它释放（不是 free/HeapFree）。 */
void XpchFree(void *Memory);

/* UTF-16 → ANSI（ACP）。BufChars 是 Ansi 缓冲的字符数。
 * 转换失败或缓冲不足返回 FALSE。 */
BOOL XpchUtf16ToAnsi(const WCHAR *Wide, char *Ansi, ULONG AnsiChars);

#ifdef __cplusplus
}
#endif

#endif /* XPCHSDK_H */