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
#include <shellapi.h>
#include <psapi.h>
#include <ctype.h>

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
#define XPCH_CMD_ENUM_OBJECTS               0x33u  /* CmdEnumObjects → Ex/Win8  in: 无；out: 0x200000（count@+0，条目@+8/0x38） */
#define XPCH_CMD_ENUM_KERNEL_MODULES        0x3Cu  /* CmdEnumKernelModules                                              */
#define XPCH_CMD_THREAD_OPERATION           0x3Du  /* CmdThreadOperation                                                */
#define XPCH_CMD_THREAD_MONITOR             0x3Eu  /* CmdThreadMonitor                                                  */
#define XPCH_CMD_STUB_ALWAYS_TRUE           0x7Fu  /* CmdStubAlwaysTrue         (0x95 槽)                               */
#define XPCH_CMD_QUERY_DRIVER_OBJECTS       0x42u  /* CmdQuerySsdtInfo（实为通用选择子枚举）
                                                       in: 24 字节 {u8 selector; pad; u64 out; u32 outSize}
                                                       → CmdEnumDriverObjects(out, outSize, 0, selector)
                                                       selector=0 时输出驱动对象列表（count@+0，
                                                       记录@+8，步长 0x228：基址@+24、大小@+32、
                                                       名称@+36 UTF-16）；原版客户端用它做符号解析 */
#define XPCH_CMD_GET_TDI_CALLBACKS          0xE6u  /* CmdGetSsdtTableInfo（实为 TDI 两处导出指针查询）
                                                       out: 6 个 QWORD，OutSize=48；[2]/[3] 原始值，
                                                       [4]/[5] 内核数据节区当前值（*GT884/*GT885） */
#define XPCH_CMD_RESTORE_TDI_CALLBACKS      0xE7u  /* CmdRestoreSsdtTable（实为把 [2]/[3] 写回内核） */
#define XPCH_CMD_ENUM_TDI_PNP_CLIENTS       0xE8u  /* CmdEnumObjectTypeInfo（实为 TDI PnP 客户端记录）
                                                       out: 4MB；total@+0、count@+4；记录步长 0x238：
                                                       类型@+8、对象@+16、名称@+24（UTF-16）、
                                                       +536/+544/+552/+560/+568 五个 handler 槽 */
#define XPCH_CMD_ENUM_NDIS_OFFLOAD          0xEAu  /* CmdQuerySsdtDetails（实为 NdisTcpOffloadHandlers 7 项）
                                                       out: 176B；count@+0；记录@+8 步长 24：
                                                       原始@+0、当前@+8、名称@+16（客户端本地补，
                                                       见 off_1406D49B0 的 7 个名字） */
#define XPCH_CMD_ENUM_NDIS_OID_TABLE        0xECu  /* CmdReadExportDirectory（实为 NdisOidTable 双表）
                                                       out: 2MB；前半当前表、后半原始表（+0x100000），
                                                       记录步长 24：类型ID@+0、PreFun@+8、PostFun@+16；
                                                       类型ID→名称见 inc/xpc_oid_names.h (738 项) */

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

/* 握手：发 0x22 合法许可包置位就绪标志，再用 0x24 验证整条链路 */
BOOL XpchHandshake(PXPCH_CLIENT Client);

/* 构造 0x22 用的 0x100 字节许可包（AES-128 + MD5 + 时间窗） */
BOOL XpchBuildLicensePacket(UCHAR OutHex[0x100]);

/* AES-128 单块加密（供许可包构造） */
void XpchAes128EncryptBlock(const UCHAR Key[16], const UCHAR In[16], UCHAR Out[16]);

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

/* ---- Process 页子视图（src/ProcessViews.c）---- */
#define FE_WINDOW_ENTRY_TITLE_CHARS 256u

typedef struct _FE_WINDOW_ENTRY {
    ULONG64 Hwnd;
    ULONG   ThreadId;
    ULONG   ProcessId;
    char    ClassName[128];
    WCHAR   Title[FE_WINDOW_ENTRY_TITLE_CHARS];
} FE_WINDOW_ENTRY;

typedef struct _FE_WINDOW_LIST {
    ULONG             Count;
    ULONG             Capacity;
    FE_WINDOW_ENTRY  *Items;
} FE_WINDOW_LIST;

BOOL FeLoadProcessWindows(ULONG Pid, ULONG MaxCount, FE_WINDOW_LIST *List);
void FeFreeProcessWindows(FE_WINDOW_LIST *List);
BOOL FePrintProcessWindows(ULONG Pid);

/* ---- Modules 子视图（psapi，纯用户态）---- */
#define FE_MODULE_PATH_CHARS 260u

/* ---- Kernel 页：Kernel Module / Driver 两个子页 ----
 *
 * Kernel Module：已加载的内核模块（ntoskrnl/hal/各 .sys）。
 *   数据源 psapi 的 EnumDeviceDrivers + GetDeviceDriverBaseNameW/FileNameW
 *   （驱动侧 0x25/0x3C 的移植缺陷见 docs/reversing/GT槽号审计 与
 *     Process页落地 的说明；等 0x25 实机验通后再作为主源替换）。
 *   EnumDeviceDrivers 只给基址，**大小由相邻基址差值推算**（按基址排序后）。
 *
 * Driver：系统里注册的内核驱动服务（注册表 Services + SCM 状态）。
 *   数据源 OpenSCManager + EnumServicesStatusEx(SERVICE_DRIVER) + QueryServiceConfig。
 */
#define FE_KMOD_NAME_CHARS 64u
#define FE_KMOD_PATH_CHARS 320u

typedef struct _FE_KMODULE {
    ULONG64 Base;
    ULONG64 Size;                              /* 相邻基址差值；最后一个为 0 */
    char    Name[FE_KMOD_NAME_CHARS];          /* 映像名，如 ntoskrnl.exe */
    char    Path[FE_KMOD_PATH_CHARS];          /* \SystemRoot\System32\... */
} FE_KMODULE;

typedef struct _FE_KMODULE_LIST {
    ULONG        Count;
    ULONG        Capacity;
    FE_KMODULE  *Items;
} FE_KMODULE_LIST;

BOOL FeLoadKernelModules(FE_KMODULE_LIST *List);
void FeFreeKernelModules(FE_KMODULE_LIST *List);
BOOL FePrintKernelModules(void);

#define FE_DRV_NAME_CHARS  128u
#define FE_DRV_PATH_CHARS  320u
#define FE_DRV_DISP_CHARS  160u

typedef struct _FE_DRIVER {
    char  Name[FE_DRV_NAME_CHARS];             /* 服务名 */
    char  Display[FE_DRV_DISP_CHARS];
    char  Path[FE_DRV_PATH_CHARS];             /* ImagePath */
    DWORD State;                               /* SERVICE_RUNNING 等 */
    DWORD Start;                               /* SERVICE_BOOT_START 等 */
    DWORD Type;                                /* SERVICE_KERNEL_DRIVER / FILE_SYSTEM_DRIVER */
} FE_DRIVER;

typedef struct _FE_DRIVER_LIST {
    ULONG       Count;
    ULONG       Capacity;
    FE_DRIVER  *Items;
} FE_DRIVER_LIST;

BOOL FeLoadDrivers(FE_DRIVER_LIST *List);
void FeFreeDrivers(FE_DRIVER_LIST *List);
BOOL FePrintDrivers(void);

/* ---- Hidden Drivers / Suspicious DriverObject ----
 * 判据：内核已加载模块的文件名在 SCM 驱动服务里找不到对应项（隐藏），
 * 以及路径不在系统目录、磁盘无文件、或文件名不是 *.sys（可疑驱动对象）。 */
#define FE_HDRV_NAME_CHARS 64u
#define FE_HDRV_PATH_CHARS 320u
#define FE_HDRV_REASON_CHARS 192u

typedef struct _FE_HDRV_ENTRY {
    char    Name[FE_HDRV_NAME_CHARS];
    ULONG64 Base;
    ULONG64 Size;
    char    Path[FE_HDRV_PATH_CHARS];
    char    Reason[FE_HDRV_REASON_CHARS];
} FE_HDRV_ENTRY;

typedef struct _FE_HDRV_LIST {
    ULONG          Count;
    ULONG          Capacity;
    FE_HDRV_ENTRY *Items;
} FE_HDRV_LIST;

BOOL FeLoadHiddenDrivers(FE_HDRV_LIST *Hidden, FE_HDRV_LIST *Suspicious);
void FeFreeHiddenDrivers(FE_HDRV_LIST *List);
BOOL FePrintHiddenDrivers(void);

/* ---- Kernel 页状态栏的其他内核项 ---- */
BOOL FeCheckKiDebugRoutine(ULONG64 *pValue, BOOL *pHooked,
                           char *Detail, size_t DetailChars);
BOOL FeFindPteHook(char *Detail, size_t DetailChars, BOOL *pHooked);

/* ---- IDT / I/O Port（0x046，输出 >= 0x3808）----
 * 输出：+0x00 DWORD 已写上下文数 n，+0x08 起 n 个 0x3800 字节上下文。
 * 每个上下文里第 i 条 56 字节：+0 DWORD 向量号，+8 QWORD 处理函数 RVA
 * （驱动写的是 handler - ntoskrnlBase；0 表示空门）。 */
#define FE_IDT_MAX 256

typedef struct _FE_IDT_ENTRY {
    ULONG   Vector;
    ULONG64 HandlerRva;
} FE_IDT_ENTRY;

typedef struct _FE_IDT_LIST {
    ULONG         ContextCount;
    ULONG         Count;        /* 第一个上下文的条目数 */
    FE_IDT_ENTRY *Items;
    BOOL          DriverOk;
    UCHAR         ResultByte;
} FE_IDT_LIST;

BOOL FeLoadIdt(XPCH_CLIENT *Client, FE_IDT_LIST *List);
void FeFreeIdt(FE_IDT_LIST *List);
BOOL FePrintIdt(XPCH_CLIENT *Client);

/* ---- SSDT 恢复（原版 SSDT 页状态栏 Restore / Restore All）----
 * 0xE7 全量恢复服务表描述符；0xEB 按选择子 0..6 恢复单个表项/计数。 */
BOOL FeRestoreSsdtAll(XPCH_CLIENT *Client, BYTE *pResult);
BOOL FeRestoreSsdtEntry(XPCH_CLIENT *Client, ULONG Selector, BYTE *pResult);

/* ---- Driver 子页操作（原版右键菜单）----
 * 全部走 SCM + WinVerifyTrust，不依赖驱动。 */
BOOL FeResolveDriverPath(const char *ServiceName, char *Out, size_t OutChars);
BOOL FeUnloadDriverService(const char *ServiceName, DWORD *pError);
BOOL FeDeleteDriverFile(const char *ServiceName, char *DeletedPath,
                        size_t PathChars, DWORD *pError);
BOOL FeDeleteDriverFileAndReg(const char *ServiceName, char *DeletedPath,
                              size_t PathChars, DWORD *pFileErr, DWORD *pRegErr);
void FeVerifyAllDrivers(ULONG *pValid, ULONG *pInvalid, ULONG *pMissing, ULONG *pTotal);
BOOL FeDriverOpsCli(const char *CmdLine);

/* ---- Startup Info 页（原版第 7 个主 Tab）----
 * 覆盖 16 类自启动位置；全部是注册表读取，不依赖驱动。
 * Wow64 视图分别枚举（32/64），与原版"含 Wow64 版本"一致。 */
#define FE_STARTUP_LOC_CHARS  96u
#define FE_STARTUP_NAME_CHARS 256u
#define FE_STARTUP_DATA_CHARS 512u
#define FE_STARTUP_KEY_CHARS  512u

typedef struct _FE_STARTUP_ENTRY {
    char Location[FE_STARTUP_LOC_CHARS];   /* 位置标签 */
    char Name[FE_STARTUP_NAME_CHARS];      /* 值名 / 子键名 */
    char Data[FE_STARTUP_DATA_CHARS];      /* 命令行 / DLL 路径 */
    char Hive[8];                          /* "HKLM" / "HKCU" */
    char SubKey[FE_STARTUP_KEY_CHARS];     /* 注册表子键（删除/复制路径用） */
    ULONG View;                            /* 64 / 32（Wow64） */
} FE_STARTUP_ENTRY;

typedef struct _FE_STARTUP_LIST {
    ULONG              Count;
    ULONG              Capacity;
    FE_STARTUP_ENTRY  *Items;
} FE_STARTUP_LIST;

BOOL FeLoadStartupItems(FE_STARTUP_LIST *List);
void FeFreeStartupItems(FE_STARTUP_LIST *List);
BOOL FePrintStartupItems(void);
BOOL FeDeleteStartupItem(const FE_STARTUP_ENTRY *Item);

/* Startup Info 的两项破坏性操作（原版右键菜单） */
BOOL FeDeleteStartupItemAndFile(const FE_STARTUP_ENTRY *Item,
                                char *DeletedPath, size_t PathChars,
                                BOOL *pRegDeleted, DWORD *pFileError);
ULONG FeRepairStartupItems(ULONG *pChecked, FE_STARTUP_LIST *Repaired);

typedef struct _FE_MODULE_ENTRY {
    ULONG64 Base;
    ULONG   Size;
    WCHAR   Path[FE_MODULE_PATH_CHARS];
    WCHAR   Name[64];
} FE_MODULE_ENTRY;

typedef struct _FE_MODULE_LIST {
    ULONG             Count;
    ULONG             Capacity;
    FE_MODULE_ENTRY  *Items;
} FE_MODULE_LIST;

BOOL FeLoadProcessModules(ULONG Pid, ULONG MaxCount, FE_MODULE_LIST *List);
void FeFreeProcessModules(FE_MODULE_LIST *List);
BOOL FePrintProcessModules(ULONG Pid);

/* ---- Threads 子视图（Toolhelp32，纯用户态）---- */
typedef struct _FE_THREAD_ENTRY {
    ULONG   ThreadId;
    ULONG   OwnerPid;
    LONG    BasePriority;
    LONG    PriorityDelta;
    ULONG64 StartAddress;
} FE_THREAD_ENTRY;

typedef struct _FE_THREAD_LIST {
    ULONG             Count;
    ULONG             Capacity;
    FE_THREAD_ENTRY  *Items;
} FE_THREAD_LIST;

BOOL FeLoadProcessThreads(ULONG Pid, ULONG MaxCount, FE_THREAD_LIST *List);
void FeFreeProcessThreads(FE_THREAD_LIST *List);
BOOL FePrintProcessThreads(ULONG Pid);

/* ---- Handles 子视图（NtQuerySystemInformation）---- */
typedef struct _FE_HANDLE_ENTRY {
    ULONG64 Handle;
    ULONG64 Object;
    ULONG   TypeIndex;
    ULONG   Access;
    ULONG   Attributes;
    char    TypeName[64];
} FE_HANDLE_ENTRY;

typedef struct _FE_HANDLE_LIST {
    ULONG             Count;
    ULONG             Capacity;
    FE_HANDLE_ENTRY  *Items;
} FE_HANDLE_LIST;

BOOL FeLoadProcessHandles(ULONG Pid, ULONG MaxCount, FE_HANDLE_LIST *List);
void FeFreeProcessHandles(FE_HANDLE_LIST *List);
BOOL FePrintProcessHandles(ULONG Pid);

/* ---- Memory 子视图（VirtualQueryEx）---- */
#define FE_MEMORY_NAME_CHARS 260u

typedef struct _FE_MEMORY_ENTRY {
    ULONG64 Base;
    ULONG64 Size;
    ULONG   Protect;
    ULONG   State;
    ULONG   Type;
    WCHAR   Name[FE_MEMORY_NAME_CHARS];
} FE_MEMORY_ENTRY;

typedef struct _FE_MEMORY_LIST {
    ULONG              Count;
    ULONG              Capacity;
    FE_MEMORY_ENTRY   *Items;
} FE_MEMORY_LIST;

BOOL FeLoadProcessMemory(ULONG Pid, ULONG MaxCount, FE_MEMORY_LIST *List);
void FeFreeProcessMemory(FE_MEMORY_LIST *List);
BOOL FePrintProcessMemory(ULONG Pid);

/* ---- 进程操作（0x28 / 0xA2，破坏性）---- */
BOOL FeKillProcess(XPCH_CLIENT *Client, ULONG Pid, ULONG64 Eprocess, BOOL ByEprocess);

/* ---- Process 页进程操作（原版右键菜单）---- */
BOOL FeForceKillProcess(XPCH_CLIENT *Client, ULONG Pid);
BOOL FeSuspendResumeProcess(ULONG Pid, BOOL Suspend);
ULONG FeCollectProcessTree(ULONG RootPid, ULONG *Pids, ULONG MaxPids);
BOOL FeKillProcessTree(XPCH_CLIENT *Client, ULONG RootPid,
                       ULONG *pKilled, ULONG *pFailed);
BOOL FeGetProcessImagePath(ULONG Pid, char *Out, size_t OutChars);
BOOL FeKillAndDeleteProcessFile(XPCH_CLIENT *Client, ULONG Pid,
                                char *DeletedPath, size_t PathChars,
                                DWORD *pError, BOOL *pRebootDelete);
BOOL FeDumpMemoryToFile(ULONG Pid, ULONG64 Base, ULONG64 Size,
                        const char *OutPath, ULONG64 *pWritten);

/* ---- Process 页状态栏：Processes / Hidden / Ring3 Inaccessible ---- */
BOOL FeIsProcessRing3Accessible(ULONG Pid);
BOOL FeComputeProcessStatus(const FE_PROCESS_LIST *List,
                            ULONG *pHidden, ULONG *pInaccessible,
                            BOOL *pInaccessibleFlags);

/* View Timer：按句柄类型名 "Timer" 过滤（用户态全系统句柄表）。 */
BOOL FeLoadProcessTimers(ULONG Pid, ULONG MaxCount, FE_HANDLE_LIST *List);

/* ---- View HotKey（驱动 0x33 CmdEnumObjects，Win8 链表枚举）----
 * 原版 PCHunter64.exe 的 CProcessHotkeyDialog 用 0x33 取热键表：
 *   输出缓冲：+0x00 count，+0x08 起每条 0x38 字节
 *   条目：+0x00 桶指针、+0x08 桶[2]、+0x10 桶[8]（0x%08X）、
 *         +0x14 修饰键（word：8=Win 2=Ctrl 1=Alt 4=Shift）、+0x18 VK（dword）、
 *         +0x20 PID（%d）、+0x28 EPROCESS（0x%p，对话框按它过滤）、+0x30 TID（%d）
 * 条目基址在 +0x08（原驱动 CmdEnumObjectsEx 用 _QWORD* pOutputBuffer + 1）。 */
#define FE_HOTKEY_NAME_CHARS      64u
#define FE_HOTKEY_PROC_NAME_CHARS 128u

typedef struct _FE_HOTKEY_ENTRY {
    ULONG64 Bucket;      /* 热键链表桶指针（对话框第 1 列） */
    ULONG   Flags;       /* 桶[8]（对话框第 2 列，0x%08X） */
    ULONG   Modifiers;   /* 8=Win 2=Ctrl 1=Alt 4=Shift */
    ULONG   VirtualKey;  /* 虚拟键码 */
    ULONG   Pid;         /* 归属进程 */
    ULONG   Tid;         /* 归属线程 */
    ULONG64 Eprocess;    /* 归属进程对象（对话框过滤依据） */
    WCHAR   Hotkey[FE_HOTKEY_NAME_CHARS]; /* 如 "Ctrl + Alt + A" */
    char    ProcessName[FE_HOTKEY_PROC_NAME_CHARS];
} FE_HOTKEY_ENTRY;

typedef struct _FE_HOTKEY_LIST {
    ULONG            Count;
    ULONG            Capacity;
    FE_HOTKEY_ENTRY *Items;
} FE_HOTKEY_LIST;

/* 按原版 sub_14004D2F0 拼 "Ctrl + Alt + A" 形式的热键名 */
void FeFormatHotkey(WCHAR *Out, size_t OutChars, ULONG Modifiers, ULONG VirtualKey);

/* 取全系统热键表并按 EPROCESS 过滤（Eprocess=0 表示不过滤，对应原版对话框
 * 的“全部进程”模式）。调用者先打开设备（XpchOpen）。 */
BOOL FeLoadProcessHotkeys(XPCH_CLIENT *Client, ULONG64 Eprocess,
                          ULONG MaxCount, FE_HOTKEY_LIST *List);
void FeFreeProcessHotkeys(FE_HOTKEY_LIST *List);
BOOL FePrintProcessHotkeys(XPCH_CLIENT *Client, ULONG Pid);

/* ---- 模块搜索（原版 Modules 视图的五项 F 菜单）---- */
#define FE_MSEARCH_NAME_CHARS   128u
#define FE_MSEARCH_DETAIL_CHARS 320u

typedef struct _FE_MODSEARCH_ENTRY {
    ULONG   Pid;
    ULONG64 Base;
    ULONG64 Size;
    char    Name[FE_MSEARCH_NAME_CHARS];
    char    Detail[FE_MSEARCH_DETAIL_CHARS];
} FE_MODSEARCH_ENTRY;

typedef struct _FE_MODSEARCH_LIST {
    ULONG               Count;
    ULONG               Capacity;
    FE_MODSEARCH_ENTRY *Items;
} FE_MODSEARCH_LIST;

BOOL FeFindModulesByName(const char *Needle, FE_MODSEARCH_LIST *List);
BOOL FeFindUnsignedModules(int StrictNoSignatureDir, FE_MODSEARCH_LIST *List);
BOOL FeFindTargetRegions(ULONG Pid, FE_MODSEARCH_LIST *List);
BOOL FeFindHiddenModules(FE_MODSEARCH_LIST *List);
void FeFreeModSearch(FE_MODSEARCH_LIST *List);

/* ---- Services 页（原版第 8 个主 Tab，9 项）----
 * 数据源：SCM 枚举 + 注册表 Services 子树（取原始 ImagePath / ServiceDll）
 * 隐藏服务判定：注册表 Services 下有子键、但 SCM 清单里没有。 */
#define FE_SVC_NAME_CHARS   160u
#define FE_SVC_DISP_CHARS   192u
#define FE_SVC_PATH_CHARS   512u

typedef struct _FE_SERVICE_ENTRY {
    char  Name[FE_SVC_NAME_CHARS];
    char  Display[FE_SVC_DISP_CHARS];
    char  ImagePath[FE_SVC_PATH_CHARS];      /* 注册表原始值 */
    char  ResolvedPath[FE_SVC_PATH_CHARS];   /* 去引号+展开环境变量后的 exe */
    char  ServiceDll[FE_SVC_PATH_CHARS];
    DWORD State;
    DWORD Start;
    DWORD Type;
} FE_SERVICE_ENTRY;

typedef struct _FE_SERVICE_LIST {
    ULONG             Count;
    ULONG             Capacity;
    FE_SERVICE_ENTRY *Items;
    ULONG             HiddenCount;       /* 注册表有、SCM 无 */
    ULONG             RegServiceCount;   /* 注册表 Services 子键总数 */
} FE_SERVICE_LIST;

BOOL FeLoadServices(FE_SERVICE_LIST *List);
void FeFreeServices(FE_SERVICE_LIST *List);
BOOL FePrintServices(void);
BOOL FeDeleteService(const char *ServiceName);
int  FeVerifyFileSignature(const char *Path);
extern LONG g_LastTrustStatus;   /* 诊断：WinVerifyTrust 原始返回值 */

/* ---- Registry 页（原版第 6 个主 Tab，5 项）----
 * Reg Handle      : 全系统 ObjectType = "Key" 的句柄
 * Hidden Item     : 控制字符/尾随空格键名 + HKCU\Software\Classes 独占项
 * Copy Key/RegPath/RegValue/RegData : 由 GUI 列承载 */
#define FE_REGH_MAX 400000u
#define FE_REGH_PATH_CHARS 512u

typedef struct _FE_REG_HANDLE_ENTRY {
    ULONG64 Object;
    ULONG64 Handle;
    ULONG   Pid;
    ULONG   Access;
} FE_REG_HANDLE_ENTRY;

typedef struct _FE_REG_HANDLE_LIST {
    ULONG                Count;
    ULONG                Capacity;
    FE_REG_HANDLE_ENTRY *Items;
    int                  KeyTypeIndex;   /* "Key" 的对象类型索引，-1 表示没找到 */
} FE_REG_HANDLE_LIST;

BOOL FeLoadRegistryHandles(ULONG MaxCount, FE_REG_HANDLE_LIST *List);
void FeFreeRegistryHandles(FE_REG_HANDLE_LIST *List);
BOOL FePrintRegistryHandles(void);

typedef struct _FE_REG_HIDDEN_ENTRY {
    char Path[FE_REGH_PATH_CHARS];
    char Reason[192];
    int  Depth;
} FE_REG_HIDDEN_ENTRY;

typedef struct _FE_REG_HIDDEN_LIST {
    ULONG                Count;
    ULONG                Capacity;
    FE_REG_HIDDEN_ENTRY *Items;
} FE_REG_HIDDEN_LIST;

BOOL FeLoadHiddenRegKeys(FE_REG_HIDDEN_LIST *List);
void FeFreeHiddenRegKeys(FE_REG_HIDDEN_LIST *List);
BOOL FePrintHiddenRegKeys(void);

/* ---- Registry 页「Key」子页：按路径读取某个键的值 ----
 * 路径写法：HKLM\SYSTEM\CurrentControlSet\Services\ACPI（根名大小写不敏感，
 * 也接受 HKEY_LOCAL_MACHINE / HKCU / HKCR / HKU / HKCC）。 */
#define FE_REGV_NAME_CHARS 256u
#define FE_REGV_DATA_CHARS 512u

typedef struct _FE_REG_VALUE_ENTRY {
    char Name[FE_REGV_NAME_CHARS];   /* "(Default)" 表示空名值 */
    char Type[48];
    char Data[FE_REGV_DATA_CHARS];
} FE_REG_VALUE_ENTRY;

typedef struct _FE_REG_VALUE_LIST {
    ULONG               Count;
    ULONG               Capacity;
    FE_REG_VALUE_ENTRY *Items;
    DWORD               LastError;
} FE_REG_VALUE_LIST;

BOOL FeLoadRegValues(const char *Path, FE_REG_VALUE_LIST *List);
void FeFreeRegValues(FE_REG_VALUE_LIST *List);
BOOL FePrintRegValues(const char *Path);

/* ---- File 页（原版第 9 个主 Tab，10 项）----
 * 目录浏览 + 隐藏文件判定 + 占用检测 + 待删检测 + 签名校验 + 迷你反汇编。 */
#define FE_FILE_NAME_CHARS 260u
#define FE_FILE_PATH_CHARS 520u

typedef struct _FE_FILE_ENTRY {
    char    Name[FE_FILE_NAME_CHARS];
    char    Path[FE_FILE_PATH_CHARS];
    ULONG64 Size;
    DWORD   Attributes;
    ULONG   LockedCount;
    ULONG   LockOwners[4];
    unsigned char IsDir;
    unsigned char Suspect;         /* 名字可疑（标红 / 加括号） */
    unsigned char DeletePending;   /* 已标记删除但仍被持有 */
} FE_FILE_ENTRY;

typedef struct _FE_FILE_LIST {
    ULONG          Count;
    ULONG          Capacity;
    FE_FILE_ENTRY *Items;
    ULONG          HiddenCount;
    ULONG          PendingCount;
    ULONG          LockedCount;
} FE_FILE_LIST;

BOOL FeLoadDirectory(const char *Dir, FE_FILE_LIST *List);
void FeFreeDirectory(FE_FILE_LIST *List);
BOOL FePrintDirectory(const char *Dir);
BOOL FeDeleteFileEx(const char *Path, DWORD *pError);
BOOL FeCopyFileEx(const char *From, const char *To, DWORD *pError);

typedef struct _FE_INSN {
    char Mnemonic[32];
    unsigned char Length;
} FE_INSN;
int FeDisasmOne(const unsigned char *Code, int Remaining, FE_INSN *Out);

/* ---- Other 页（原版第 14 个主 Tab，4 项）---- */
typedef struct _FE_OS_INFO {
    ULONG Major, Minor, Build, UBR, PlatformId;
    char  ProductName[160];
    char  DisplayVersion[64];
    char  CurrentBuild[32];
    char  VersionString[64];
    char  MarketName[96];
} FE_OS_INFO;

BOOL FeLoadOsInfo(FE_OS_INFO *Info);
BOOL FePrintOsInfo(void);

typedef struct _FE_FILE_VER {
    ULONG FileVersionMS, FileVersionLS, ProductVersionMS, ProductVersionLS;
    ULONG FileFlags, FileOS, FileType;
    char  FileVersion[48];
    char  FileVersionStr[64];
    char  CompanyName[192];
    char  FileDescription[256];
    char  ProductName[192];
    char  InternalName[96];
    char  OriginalFilename[128];
} FE_FILE_VER;

BOOL FeLoadFileVersion(const char *Path, FE_FILE_VER *Out);
BOOL FePrintFileVersion(const char *Path);
BOOL FeBuildOnlineQueryUrl(const char *Query, int Target, char *Out, size_t OutChars);
BOOL FeOpenUrl(const char *Url);

/* ---- Examination 页（原版第 10 个主 Tab，7 项）----
 * 体检报告：汇总各页检测结果，可中断、可导出。 */
#define FE_EXAM_MAX_ITEMS 64u

typedef struct _FE_EXAM_ITEM {
    int  Severity;              /* 0=INFO 1=WARN 2=RISK */
    char Title[96];
    char Detail[320];
} FE_EXAM_ITEM;

typedef struct _FE_EXAM_RESULT {
    ULONG          Count;
    ULONG          Capacity;
    FE_EXAM_ITEM  *Items;
    ULONG          RiskCount;
    ULONG          WarnCount;
    ULONG          InfoCount;
    int            Cancelled;
    char           Date[32];
} FE_EXAM_RESULT;

BOOL FeRunExamination(FE_EXAM_RESULT *R);
void FeFreeExamination(FE_EXAM_RESULT *R);
BOOL FeExportExamination(const FE_EXAM_RESULT *R, const char *Path);
BOOL FePrintExamination(void);
void FeExamCancel(void);
void FeExamResetCancel(void);
int  FeExamIsCancelled(void);

/* ---- Fireeye 页（原版第 12 个主 Tab，7 项）----
 * 云查客户端。**不自动发起网络请求**：
 *   只做本地判定（微软签名 → 拒绝上传）、生成哈希查询 URL、记录上传历史。
 *   文件本体上传未实现（火眼 API key 已失效）。 */
typedef struct _FE_FIREEYE_JOB {
    char Path[FE_FILE_PATH_CHARS];
    char Sha256[72];
    char Company[192];
    char Message[192];
    int  IsMicrosoft;
} FE_FIREEYE_JOB;

/* 返回：2=微软文件拒绝上传 1=可查询 0=失败 */
int  FeFireeyePrecheck(const char *Path, FE_FIREEYE_JOB *Job);
BOOL FeFireeyeBuildUrl(const FE_FIREEYE_JOB *Job, char *Out, size_t OutChars);
void FeFireeyeMsMessage(const char *FileName, char *Out, size_t OutChars);
BOOL FeFileSha256(const char *Path, char *OutHex, size_t OutChars);

typedef struct _FE_FIREEYE_RECORD {
    char Time[32];
    char Sha256[72];
    char Path[FE_FILE_PATH_CHARS];
} FE_FIREEYE_RECORD;

typedef struct _FE_FIREEYE_RECORD_LIST {
    ULONG               Count;
    ULONG               Capacity;
    FE_FIREEYE_RECORD  *Items;
} FE_FIREEYE_RECORD_LIST;

BOOL   FeFireeyeAddRecord(const FE_FIREEYE_JOB *Job);
ULONG  FeFireeyeRecordCount(void);
BOOL   FeFireeyeListRecords(FE_FIREEYE_RECORD_LIST *List);
void   FeFireeyeFreeRecords(FE_FIREEYE_RECORD_LIST *List);
BOOL   FeFireeyeDeleteRecords(void);
BOOL   FePrintFireeye(const char *Path);

/* ---- Setting 页（原版第 11 个主 Tab，9 项）---- */
typedef struct _FE_OBJ_TYPES {
    ULONG64 File;
    ULONG64 Driver;
    ULONG64 Device;
    ULONG64 Process;    /* Extra[0] = GT[0x4166]，WinDbg `ln` 确认 = PsProcessType */
    ULONG64 Thread;     /* Extra[3] = GT[0x4169]，WinDbg `ln` 确认 = PsThreadType */
    ULONG64 Extra[13];
} FE_OBJ_TYPES;

BOOL FeSettingReadObjectTypes(XPCH_CLIENT *Client, FE_OBJ_TYPES *Out);
BOOL FeSettingSetForbid(XPCH_CLIENT *Client, ULONG64 TargetObject, ULONG OperationType,
                        int Enable, UCHAR *pResult);
BOOL FeSettingSelfProtect(XPCH_CLIENT *Client, int Enable);
BOOL FeSettingGetMinimizeToTray(void);
BOOL FeSettingSetMinimizeToTray(BOOL Enable);

/* ---- Trojan Detection 页（原版第 13 个主 Tab，10 项）----
 * MBR 读写走用户态 \.\PhysicalDriveN（驱动 0xCA/0xCC 仍是空槽）。 */
#define FE_MBR_SIZE 512u

typedef struct _FE_TROJAN_REPORT {
    int    MbrState;              /* 0=OK 1=Unknown 2=read failed 3=backup found */
    char   MbrDetail[256];
    BYTE   MbrSector[FE_MBR_SIZE];
    BYTE   BackupMbr[FE_MBR_SIZE];
    ULONG64 BackupSector;         /* 找到备份原始 MBR 的扇区号；0=没找到 */
    int    ZeroAccess;            /* 1 = 命中 ZeroAccess 特征 */
    int    LspOk;
    char   LspDetail[256];
    int    SafebootOk;
    char   SafebootDetail[256];
} FE_TROJAN_REPORT;

BOOL FeReadMbrSector(int DriveIndex, ULONG64 SectorIndex, BYTE Out[512], DWORD *pError);
BOOL FeWriteMbrSector(int DriveIndex, ULONG64 SectorIndex, const BYTE In[512], DWORD *pError);
int  FeCheckMbr(const BYTE Mbr[512], char *Detail, size_t DetailChars);
BOOL FeFindZeroAccess(int DriveIndex, FE_TROJAN_REPORT *R);
BOOL FeBackupMbr(int DriveIndex, const char *Path, FE_TROJAN_REPORT *R);
BOOL FeRestoreMbr(int DriveIndex, const char *Path, DWORD *pError);
BOOL FeCheckLsp(FE_TROJAN_REPORT *R);
BOOL FeCheckSafeboot(FE_TROJAN_REPORT *R);
BOOL FeRepairSafeboot(void);
BOOL FePrintTrojanReport(int DriveIndex);

/* ---- Ring0/Ring3 Hooks 页（原版第 3、4 个主 Tab，共 5 项）----
 * Ring3：用户态扫 IAT 是否指向所有已加载模块之外。
 * Ring0：驱动 0x117 返回两张系统调用表（GT[0x8B7] / GT[0x8BA]），
 *        见 KernelHookViews.c 的文件头对其布局与语义的完整说明。 */
#define FE_HOOK_MAX 500u

/* 0x117 的单个条目（40 字节） */
typedef struct _FE_RING0_HOOK_ENTRY {
    ULONG   TableIndex;        /* 1 = 第一张表(SSDT)，2 = 第二张表(Shadow SSDT) */
    unsigned char FlagAddr;    /* +0x00：表项当前值 != 磁盘原始值 → 被改写 */
    unsigned char FlagBytes;   /* +0x01：内存前 16 字节 != 磁盘 16 字节 → inline patch */
    ULONG   Index;             /* +0x04：表内索引 */
    ULONG64 Current;           /* +0x08：当前地址 */
    ULONG64 Original;          /* +0x10：磁盘原始地址 */
    unsigned char Bytes[16];   /* +0x18：磁盘原始指令前 16 字节 */
    char    Disasm[96];        /* 由 Bytes 解出的助记符（仅用于展示） */
} FE_RING0_HOOK_ENTRY;

typedef struct _FE_RING0_HOOK_LIST {
    ULONG               Count;
    ULONG               Capacity;
    FE_RING0_HOOK_ENTRY *Items;
    ULONG               Build;
    ULONG               Count1;         /* 第一张表条目数 */
    ULONG               Count2;         /* 第二张表条目数 */
    ULONG               ModifiedCount;  /* 命中任一改写标志的条目数 */
} FE_RING0_HOOK_LIST;

BOOL FeLoadRing0Hooks(XPCH_CLIENT *Client, FE_RING0_HOOK_LIST *List);
BOOL FeParseRing0Hooks(const BYTE *Buf, ULONG BufSize, FE_RING0_HOOK_LIST *List);
void FeFreeRing0Hooks(FE_RING0_HOOK_LIST *List);
BOOL FePrintRing0Hooks(XPCH_CLIENT *Client);

/* ---- Kernel 页 Device / Object 子页 ---- */
typedef struct _FE_DEVICE_ENTRY {
    ULONG   Type;
    ULONG64 DeviceObject;
    char    DriverName[520];
    char    DeviceName[520];
    char    ObjectName[520];
    char    FilePath[520];
} FE_DEVICE_ENTRY;   /* 注意：结构体内字符串按 ANSI 存，长度取源宽字符上限/2 */

typedef struct _FE_DEVICE_LIST {
    int              State;        /* 1 = 已枚举 */
    BOOL             DriverOk;
    UCHAR            ResultByte;
    ULONG            Count;
    ULONG            Capacity;
    FE_DEVICE_ENTRY *Items;
} FE_DEVICE_LIST;

BOOL FeLoadDeviceObjects(XPCH_CLIENT *Client, FE_DEVICE_LIST *Out, ULONG BufSize);
void FeFreeDeviceList(FE_DEVICE_LIST *List);

typedef struct _FE_KOBJ_ENTRY {
    ULONG64 ObjectHeader;
    ULONG64 Field1;
    ULONG64 Field2;
} FE_KOBJ_ENTRY;

typedef struct _FE_KOBJ_LIST {
    int             State;
    BOOL            DriverOk;
    UCHAR           ResultByte;
    ULONG           Build;
    ULONG           Count;
    FE_KOBJ_ENTRY  *Items;
} FE_KOBJ_LIST;

BOOL FeLoadKernelObjectTable(XPCH_CLIENT *Client, FE_KOBJ_LIST *Out);
void FeFreeKernelObjectList(FE_KOBJ_LIST *List);

/* ---- Ring0 恢复操作（清单 Tab 3 的后两项）----
 * 1) Restore Over. Hooks/Patches  -> 0x118 CmdCheckBytePattern（入 8 字节）
 * 2) Restore KernelCallbackTable  -> 0x131 枚举 + 0x132 设置（入 48 字节）
 * 两项都要能区分「没有待恢复项」与「失败」，界面据此如实呈现。 */
typedef enum _FE_HOOK_RESTORE_STATE {
    FE_HOOK_RESTORE_RESTORED = 0,
    FE_HOOK_RESTORE_NOTHING_TO_DO,          /* 无被改写条目 —— 正常状态 */
    FE_HOOK_RESTORE_ATTEMPTED_NO_EFFECT,    /* 有被改写条目但驱动未改变任何东西 */
    FE_HOOK_RESTORE_NOT_CONNECTED
} FE_HOOK_RESTORE_STATE;

typedef struct _FE_HOOK_RESTORE_RESULT {
    FE_HOOK_RESTORE_STATE State;
    BOOL      DriverOk;
    UCHAR     ResultByte;
    ULONG     ModifiedCount;    /* 0x117 报告的改写条目数 */
    ULONG     TotalEntries;
    int       TablesTried;
} FE_HOOK_RESTORE_RESULT;

BOOL FeRestoreOverHooks(XPCH_CLIENT *Client, int AllTables, FE_HOOK_RESTORE_RESULT *Out);
const char *FeHookRestoreStateText(FE_HOOK_RESTORE_RESULT *R);

typedef enum _FE_CB_STATE {
    FE_CB_ENUMERATED = 0,
    FE_CB_NOT_INITIALIZED,      /* 回调表和 GT 都为空 —— 驱动未构建，非错误 */
    FE_CB_REJECTED,
    FE_CB_NOT_CONNECTED
} FE_CB_STATE;

typedef struct _FE_CB_SLOT {
    ULONG   Offset;         /* 该槽在 28 项表中的下标（0..27） */
    ULONG   Rva;            /* 条目 +0x04：目标函数在 ntoskrnl 里的 RVA */
    ULONG64 Va;             /* 条目 +0x08：目标函数的内核虚拟地址 */
    ULONG64 Current;        /* 条目 +0x10：当前回调函数指针（EnumCallbackContextTable 填入） */
    BYTE    Original[16];   /* 条目 +0x1A：磁盘原始代码（Build 阶段从文件缓冲拷入） */
    BOOL    HasOriginal;    /* Original 是否是有效快照（FillExportEntrySlot 填的默认槽也有效） */
} FE_CB_SLOT;

typedef struct _FE_CB_TABLE {
    FE_CB_STATE State;
    BOOL        DriverOk;
    UCHAR       ResultByte;
    UCHAR       Ready;          /* 驱动 out[0]：三项校验全过才为 1 */
    ULONG       Build;
    ULONG       Count;
    FE_CB_SLOT  Slot[40];
} FE_CB_TABLE;

typedef enum _FE_CB_RESTORE_STATE {
    FE_CB_RESTORE_OK = 0,
    FE_CB_RESTORE_NO_EFFECT,
    FE_CB_RESTORE_REJECTED,
    FE_CB_RESTORE_BAD_INPUT,
    FE_CB_RESTORE_NOT_CONNECTED
} FE_CB_RESTORE_STATE;

typedef struct _FE_CB_RESTORE_RESULT {
    FE_CB_RESTORE_STATE State;
    BOOL  DriverOk;
    UCHAR ResultByte;
} FE_CB_RESTORE_RESULT;

BOOL FeLoadCallbackTable(XPCH_CLIENT *Client, FE_CB_TABLE *Out);
BOOL FeRestoreCallbackSlot(XPCH_CLIENT *Client, ULONG64 SlotAddr,
                           const BYTE *Original16, FE_CB_RESTORE_RESULT *Out);
const char *FeCbStateText(FE_CB_TABLE *T);

/* 注意：Kernel 页的 SSDT / Shadow SSDT 子页**不**用 0x117。
 * 0x117 的两张表是 Wdf01000.sys 内部的 Hook 表（见 KernelHookViews.c 文件头），
 * SSDT 用 0x8C CmdEnumSyscallEntries，Shadow SSDT 用 0x8E
 * CmdEnumShadowSyscallEntries，且两者都要求 OutSize == 1352。
 */

typedef struct _FE_HOOK_RANGE {
    ULONG64 Base;
    ULONG64 Size;
    char    Name[64];
} FE_HOOK_RANGE;

typedef struct _FE_HOOK_ENTRY {
    char    Owner[64];
    char    TargetModule[64];
    ULONG64 IatAddress;
    ULONG64 Target;
} FE_HOOK_ENTRY;

typedef struct _FE_HOOK_LIST {
    ULONG           Count;
    ULONG           Capacity;
    FE_HOOK_ENTRY  *Items;
    int             Ring0Blocked;
} FE_HOOK_LIST;

BOOL FeScanRing3Hooks(ULONG Pid, FE_HOOK_LIST *List);
void FeFreeHooks(FE_HOOK_LIST *List);
BOOL FePrintRing3Hooks(ULONG Pid);

/* ---- Network 页（原版 Network Callback 树，src/NetworkViews.c）----
 *
 * 已解码的两节（与原版客户端 sub_1400ABA60 / sub_1400ADE50 一一对应）：
 *   NdisTdiCallback : 0xE6 → 2 行；当前值 != 原始值 即 Hook（原版显示 "Hook"/"-"）
 *   TdiPnpClient    : 0xE8 → 每个客户端最多 5 个 handler 各占一行
 * 符号解析统一走 0x42（selector=0），与客户端 sub_14001F8B0 相同：
 *   按记录 {base@+24, size@+32, name@+36} 找包含该地址的模块。
 * 原版还会沿指针链最多 5 跳（sub_14001F850 → cmd 0x77），但 0x77 的处理器
 * （EnableThreadProtect，0x140007AB4）无条件返回 0，循环永不前进，故此处不实现。
 */
#define FE_NET_NAME_CHARS   260u
#define FE_NET_PATH_CHARS   520u
#define FE_NET_COMPANY_CHARS 192u

typedef struct _FE_TDI_CALLBACK_ENTRY {
    char    Name[64];                     /* 客户端本地补的名称（非驱动返回） */
    ULONG64 Current;                      /* 内核数据节区里的当前函数指针 */
    ULONG64 Original;                     /* 磁盘映像中的原始函数地址 */
    BOOL    Hooked;                       /* Current != Original */
    char    Module[FE_NET_PATH_CHARS];    /* 0x42 解析出的模块路径 */
    char    Company[FE_NET_COMPANY_CHARS];/* 该模块文件的 CompanyName */
} FE_TDI_CALLBACK_ENTRY;

typedef struct _FE_TDI_CALLBACK_LIST {
    ULONG Count;
    FE_TDI_CALLBACK_ENTRY Items[2];
} FE_TDI_CALLBACK_LIST;

typedef struct _FE_TDI_PNP_ENTRY {
    char    ClientName[FE_NET_NAME_CHARS];
    ULONG64 ClientObject;
    ULONG64 BindingHandler;      /* +536：type==1（TDI_PNP_OPCODE_BIND） */
    ULONG64 UnBindHandler;       /* +544：仅 type==1 */
    ULONG64 AddAddressHandler;   /* +552 */
    ULONG64 DelAddressHandler;   /* +560 */
    ULONG64 PnPPowerHandler;     /* +568：仅 type!=1 */
} FE_TDI_PNP_ENTRY;

typedef struct _FE_TDI_PNP_LIST {
    ULONG Count;                 /* 实际客户端数（驱动 header +4） */
    ULONG Total;                 /* 遍历到的对象总数（驱动 header +0） */
    FE_TDI_PNP_ENTRY *Items;
} FE_TDI_PNP_LIST;

/* 0xEA：NdisTcpOffloadHandlers 表（原版固定 7 项，名称是客户端本地字符串）
   驱动返回 count@+0、记录@+8 步长 24：原始@+0、当前@+8；
   名称槽 +16 由客户端按 off_1406D49B0 依次填入。 */
#define FE_NDIS_OFFLOAD_MAX 7u

typedef struct _FE_NDIS_OFFLOAD_ENTRY {
    char    Name[48];            /* 客户端本地补的名称（非驱动返回） */
    ULONG64 Current;             /* 当前生效的函数指针 */
    ULONG64 Original;            /* 表内原始函数指针 */
    BOOL    Hooked;              /* Current != Original */
    char    Module[FE_NET_PATH_CHARS];     /* 0x42 解析出的模块路径 */
    char    Company[FE_NET_COMPANY_CHARS]; /* 该模块文件的 CompanyName */
} FE_NDIS_OFFLOAD_ENTRY;

typedef struct _FE_NDIS_OFFLOAD_LIST {
    ULONG Count;
    FE_NDIS_OFFLOAD_ENTRY Items[FE_NDIS_OFFLOAD_MAX];
} FE_NDIS_OFFLOAD_LIST;

/* 0xEC：NdisOidTable（每项 {类型ID, PreFun, PostFun}，驱动同时给当前表与原始表）
   原版固定 2MB 输出：前半当前表、后半原始表（偏移 0x100000），记录步长 24，
   以全 0 记录作为结束标记。类型ID→名称用 inc/xpc_oid_names.h 的 738 项表。 */
#define FE_OID_HALF_SIZE      0x100000u
#define FE_OID_RECORD_SIZE    24u
#define FE_OID_MAX_COUNT      (FE_OID_HALF_SIZE / FE_OID_RECORD_SIZE)

typedef struct _FE_NDIS_OID_ENTRY {
    ULONG64 TypeId;
    ULONG64 CurrentPre;
    ULONG64 CurrentPost;
    ULONG64 OriginalPre;
    ULONG64 OriginalPost;
} FE_NDIS_OID_ENTRY;

typedef struct _FE_NDIS_OID_LIST {
    ULONG Count;
    FE_NDIS_OID_ENTRY *Items;
} FE_NDIS_OID_LIST;

/* 0xF0：Ndis Interface（原版客户端 sub_1400AAB70 → sub_140026220）
   输出 2MB：count@+0；记录@+8 步长 0x270。
   注意：驱动侧原始处理函数为 EnumKernelModules（0x1400669B8，模块枚举，
   输出 156 个 DWORD 的加载器记录）；原版前端直接把该记录按“接口信息”
   字段偏移格式化显示，故这里按客户端语义逐字段复制，保持 1:1。 */
#define XPCH_CMD_ENUM_NDIS_INTERFACES       0xF0u
#define FE_NDIS_IF_RECORD_SIZE   0x270u
#define FE_NDIS_IF_MAX_COUNT     0x1000u
#define FE_NDIS_IF_DESCR_CHARS   256u   /* +88 起 512 字节，客户端在 +600 强置 0 */
#define FE_NDIS_IF_LINE_COUNT    17u

typedef struct _FE_NDIS_IF_ENTRY {
    ULONG64 LoaderEntry;                 /* 记录 +0（客户端显示为 Interface 指针） */
    ULONG   Flags;                       /* +8  */
    ULONG   Mtu;                         /* +12 */
    ULONG   PromiscuousMode;             /* +16 */
    ULONG   AccessType;                  /* +20 */
    ULONG   DirectionType;               /* +24 */
    ULONG   ConnectionType;              /* +28 */
    ULONG   MediaType;                   /* +32 */
    ULONG   MediaConnectState;           /* +36 */
    ULONG   MediaDuplexState;            /* +40 */
    ULONG   AdminStatus;                 /* +44 */
    ULONG   OperStatus;                  /* +48 */
    ULONG   InterfaceGuidData1;          /* +52 */
    USHORT  InterfaceGuidData2;          /* +56 */
    USHORT  InterfaceGuidData3;          /* +58 */
    UCHAR   InterfaceGuidData4[8];       /* +60 */
    ULONG   NetworkGuidData1;            /* +68 */
    USHORT  NetworkGuidData2;            /* +72 */
    USHORT  NetworkGuidData3;            /* +74 */
    UCHAR   NetworkGuidData4[8];         /* +76 */
    ULONG   IfIndex;                     /* +84 */
    WCHAR   IfDescr[FE_NDIS_IF_DESCR_CHARS]; /* +88，512 字节 */
    ULONG64 ProviderIfContext;           /* +608 */
    ULONG64 ProviderHandle;              /* +616 */
} FE_NDIS_IF_ENTRY;

typedef struct _FE_NDIS_IF_LIST {
    ULONG Count;
    FE_NDIS_IF_ENTRY *Items;
} FE_NDIS_IF_LIST;

/* ----------------------------------------------------------------------------
 * 节点 6~10、12：通用 “指针表” 视图（原版 sub_1400A8FB0，一次反编译、六个入口）
 *   列：Index / Fun Entry / Module / File Corporation
 *   输出：ULONG Count@+0；QWORD 地址数组@+8（最多 287 项）
 *   0xF7 / 0xF9 输出仅 8 字节单值，客户端固定按 1 项处理。
 * -------------------------------------------------------------------------- */
#define XPCH_CMD_FWPS_TCPIP_TABLE      0xF1u
#define XPCH_CMD_FWPS_L2_TABLE         0xF2u
#define XPCH_CMD_WFP_NBL_TABLE         0xF3u
#define XPCH_CMD_WFP_STREAM_SHIM       0xF6u
#define XPCH_CMD_NSI_LEGACY_HANDLER    0xF7u
#define XPCH_CMD_WFP_MAC_SHIM          0xF9u

#define FE_FWPS_TABLE_MAX_ENTRIES   287u
#define FE_FWPS_LARGE_OUT_SIZE      2304u
#define FE_FWPS_SINGLE_OUT_SIZE     8u

typedef struct _FE_FWPS_TABLE {
    ULONG   Count;
    ULONG64 *Entries;
} FE_FWPS_TABLE;

/* 节点 11 NetioLayerCallback（0xF4，原版 sub_1400AC070 / 驱动 EnumKernelMemoryContext）
   输出 1MB：Count@+0；记录@+8 步长 16：{ULONG Id@+0; ULONG pad; ULONG64 Address@+8} */
#define XPCH_CMD_ENUM_KERNEL_MEMORY_CONTEXT 0xF4u
#define FE_NETIO_OUT_SIZE      0x100000u
#define FE_NETIO_RECORD_SIZE   16u
#define FE_NETIO_MAX_COUNT     5u

typedef struct _FE_NETIO_ENTRY {
    ULONG   Id;
    ULONG64 Address;
} FE_NETIO_ENTRY;

typedef struct _FE_NETIO_LIST {
    ULONG Count;
    FE_NETIO_ENTRY *Items;
} FE_NETIO_LIST;

/* 节点 13 WfpDeviceObject（0xFA，原版 sub_1400ADB40 / 驱动 CmdReadKernelMemoryRangeSize）
   输出 16 字节：Current@+0、Original@+8（后者是新分配的 Nt 句柄条目） */
#define XPCH_CMD_READ_KERNEL_MEMORY_RANGE_SIZE 0xFAu
#define FE_WFP_DEVICE_OUT_SIZE 16u

typedef struct _FE_WFP_DEVICE {
    ULONG64 Current;
    ULONG64 Original;
} FE_WFP_DEVICE;

/* 节点 14 WfpCallout（0xFC，原版 sub_1400AD4E0 / 驱动 CmdEnumKernelMemoryDetail）
   输出 4MB：Count@+0；HasFeCallout(BYTE)@+8；FeCallout 三回调@+24/+32/+40；
   Callout 记录@+48 步长 32：{Index@+0, pad, Classify@+8, Notify@+16, FlowDelete@+24} */
#define XPCH_CMD_ENUM_KERNEL_MEMORY_DETAIL 0xFCu
#define FE_WFP_CALLOUT_OUT_SIZE      0x400000u
#define FE_WFP_CALLOUT_RECORD_BASE   48u
#define FE_WFP_CALLOUT_RECORD_SIZE   32u
#define FE_WFP_CALLOUT_MAX_COUNT     0x10000u

typedef struct _FE_WFP_CALLOUT_ENTRY {
    ULONG   Index;
    ULONG64 ClassifyCallback;
    ULONG64 NotifyCallback;
    ULONG64 FlowDeleteFunction;
} FE_WFP_CALLOUT_ENTRY;

typedef struct _FE_WFP_CALLOUT_LIST {
    ULONG   Count;
    BOOL    HasFeCallout;
    ULONG64 FeClassifyCallback;
    ULONG64 FeNotifyCallback;
    ULONG64 FeFlowDeleteFunction;
    FE_WFP_CALLOUT_ENTRY *Items;
} FE_WFP_CALLOUT_LIST;

/* 节点 16 NsiChangeNotification（0xFF）
   输出 4MB：GroupCount@+0；分组@+8：{Size@+0, Count@+4, 条目@+16 步长 24：
   {Node@+0, Object@+8, Zero@+16}}；下一分组 = 本分组 + Size */
#define XPCH_CMD_ENUM_NSI_CHANGE_NOTIFICATION 0xFFu
#define FE_NSI_OUT_SIZE        0x400000u
#define FE_NSI_ENTRY_SIZE      24u
#define FE_NSI_GROUP_MAX       0x10000u

typedef struct _FE_NSI_NOTIFY_ENTRY {
    ULONG64 Node;
    ULONG64 AttachCallback;
    ULONG64 DetachCallback;
} FE_NSI_NOTIFY_ENTRY;

typedef struct _FE_NSI_NOTIFY_GROUP {
    ULONG Count;
    FE_NSI_NOTIFY_ENTRY *Items;
} FE_NSI_NOTIFY_GROUP;

typedef struct _FE_NSI_NOTIFY_LIST {
    ULONG Count;
    ULONG GroupCount;
    FE_NSI_NOTIFY_GROUP *Groups;
} FE_NSI_NOTIFY_LIST;

/* 节点 15 NmrProvider(Client)（0xFE）
   输出 4MB：GroupCount@+0；分组@+8：{Size@+0, Count@+4, NmrObject@+8,
   条目@+16 步长 40：{EntryPtr@+0, IsClient@+8, Attach@+16,
   Detach@+24, Cleanup@+32}}；下一分组 = 本分组 + Size */
#define XPCH_CMD_ENUM_NMR_PROVIDERS 0xFEu
#define FE_NMR_OUT_SIZE        0x400000u
#define FE_NMR_ENTRY_SIZE      40u
#define FE_NMR_GROUP_MAX       0x10000u

typedef struct _FE_NMR_ENTRY {
    ULONG64 EntryPtr;
    BOOL    IsClient;
    ULONG64 AttachCallback;
    ULONG64 DetachCallback;
    ULONG64 CleanupCallback;
} FE_NMR_ENTRY;

typedef struct _FE_NMR_GROUP {
    ULONG Count;
    ULONG64 NmrObject;
    FE_NMR_ENTRY *Items;
} FE_NMR_GROUP;

typedef struct _FE_NMR_LIST {
    ULONG Count;
    ULONG GroupCount;
    FE_NMR_GROUP *Groups;
} FE_NMR_LIST;

/* 节点 18 Ipsec Dispatch Fun（0x11D，OutSize=0x548）
   节点 19 Ipfltdrv Dispatch Fun（0x11F，OutSize=0xA58）
   共享块布局（块 A 在 +8，块 B 在 +1352）：
   {BYTE Valid@+0; ...; 条目@+24 步长 48：
   {QWORD Original@+8, QWORD Entry@+16, BYTE Primary@+24, BYTE Inline@+25}}
   节点 19 头：BYTE Flags@+0（bit0=A, bit1=B），BYTE ValidA@+2，
   BYTE ValidB@+3 */
#define XPCH_CMD_ENUM_IPSEC_DISPATCH   0x11Du
#define XPCH_CMD_ENUM_IPF_DISPATCH     0x11Fu
#define FE_IPSEC_OUT_SIZE              0x548u
#define FE_IPF_OUT_SIZE                0xA58u
#define FE_IPF_BLOCK_B_OFFSET          1352u
#define FE_DISPATCH_ENTRY_SIZE         48u
#define FE_DISPATCH_MAX_IRP            28u
#define FE_DISPATCH_MAX_FASTIO         27u

typedef struct _FE_DISPATCH_ENTRY {
    ULONG64 Original;
    ULONG64 Entry;
    BOOL    Primary;
    BOOL    Inline;
} FE_DISPATCH_ENTRY;

typedef struct _FE_DISPATCH_BLOCK {
    BOOL Valid;
    ULONG Count;
    FE_DISPATCH_ENTRY Entries[FE_DISPATCH_MAX_IRP];
} FE_DISPATCH_BLOCK;

typedef struct _FE_IPSEC_DISPATCH {
    FE_DISPATCH_BLOCK Irp;
} FE_IPSEC_DISPATCH;

typedef struct _FE_IPF_DISPATCH {
    ULONG Flags;
    FE_DISPATCH_BLOCK Irp;
    FE_DISPATCH_BLOCK FastIo;
} FE_IPF_DISPATCH;

/* 节点 17 NsiChangeNotification_Monitor（0x100）
   输出 4MB：Count@+0；记录@+8 步长 64：{Id@+8, Callback1..7@+16..+64} */
#define XPCH_CMD_ENUM_NSI_CHANGE_MONITOR 0x100u
#define FE_NSI_MONITOR_STRIDE  64u
#define FE_NSI_MONITOR_MAX     0x10000u

typedef struct _FE_NSI_MONITOR_ENTRY {
    ULONG64 Id;
    ULONG64 Callbacks[7];
} FE_NSI_MONITOR_ENTRY;

typedef struct _FE_NSI_MONITOR_LIST {
    ULONG Count;
    FE_NSI_MONITOR_ENTRY *Items;
} FE_NSI_MONITOR_LIST;

/* 0x42 符号表：4MB 输出缓冲，查找期间复用 */
typedef struct _FE_SYMBOL_TABLE {
    ULONG Count;
    UCHAR *Buffer;
    char  LastModule[FE_NET_PATH_CHARS];
    char  LastCompany[FE_NET_COMPANY_CHARS];
} FE_SYMBOL_TABLE;

BOOL FeOpenSymbolTable(XPCH_CLIENT *Client, FE_SYMBOL_TABLE *Table);
void FeCloseSymbolTable(FE_SYMBOL_TABLE *Table);
BOOL FeResolveSymbol(FE_SYMBOL_TABLE *Table, ULONG64 Address,
                     char *Module, size_t ModuleChars,
                     char *Company, size_t CompanyChars);

BOOL FeLoadTdiCallbacks(XPCH_CLIENT *Client, FE_TDI_CALLBACK_LIST *List);
BOOL FeRestoreTdiCallbacks(XPCH_CLIENT *Client, UCHAR *ResultByte);
BOOL FeLoadTdiPnpClients(XPCH_CLIENT *Client, FE_TDI_PNP_LIST *List);
void FeFreeTdiPnpClients(FE_TDI_PNP_LIST *List);
BOOL FeLoadNdisOffloadHandlers(XPCH_CLIENT *Client, FE_NDIS_OFFLOAD_LIST *List);
BOOL FeLoadNdisOidTable(XPCH_CLIENT *Client, FE_NDIS_OID_LIST *List);
void FeFreeNdisOidTable(FE_NDIS_OID_LIST *List);
BOOL FeLoadNdisInterfaces(XPCH_CLIENT *Client, FE_NDIS_IF_LIST *List);
void FeFreeNdisInterfaces(FE_NDIS_IF_LIST *List);
int  FeFormatNdisInterfaceLines(const FE_NDIS_IF_ENTRY *Entry,
                                char Lines[FE_NDIS_IF_LINE_COUNT][FE_NET_PATH_CHARS]);
const char *FeOidName(ULONG64 TypeId);
const char *FeFwpsTableName(ULONG Node);
BOOL FeLoadFwpsTable(XPCH_CLIENT *Client, ULONG Command, ULONG OutSize,
                     ULONG FixedCount, FE_FWPS_TABLE *Table);
void FeFreeFwpsTable(FE_FWPS_TABLE *Table);
BOOL FePrintFwpsTable(XPCH_CLIENT *Client, ULONG Node);
BOOL FeLoadNetioLayerCallbacks(XPCH_CLIENT *Client, FE_NETIO_LIST *List);
void FeFreeNetioLayerCallbacks(FE_NETIO_LIST *List);
BOOL FePrintNetioLayerCallbacks(XPCH_CLIENT *Client);
BOOL FeLoadWfpDeviceObject(XPCH_CLIENT *Client, FE_WFP_DEVICE *Device);
BOOL FeLoadWfpCallouts(XPCH_CLIENT *Client, FE_WFP_CALLOUT_LIST *List);
void FeFreeWfpCallouts(FE_WFP_CALLOUT_LIST *List);
BOOL FePrintWfpCallouts(XPCH_CLIENT *Client);
BOOL FeLoadNsiChangeNotifications(XPCH_CLIENT *Client, FE_NSI_NOTIFY_LIST *List);
void FeFreeNsiChangeNotifications(FE_NSI_NOTIFY_LIST *List);
BOOL FePrintNsiChangeNotifications(XPCH_CLIENT *Client);
BOOL FeLoadNsiChangeMonitor(XPCH_CLIENT *Client, FE_NSI_MONITOR_LIST *List);
void FeFreeNsiChangeMonitor(FE_NSI_MONITOR_LIST *List);
BOOL FePrintNsiChangeMonitor(XPCH_CLIENT *Client);
BOOL FeLoadNmrProviders(XPCH_CLIENT *Client, FE_NMR_LIST *List);
void FeFreeNmrProviders(FE_NMR_LIST *List);
BOOL FePrintNmrProviders(XPCH_CLIENT *Client);
extern const char *g_NvIrpNames[];
extern const char *g_NvFastIoNames[];
BOOL FeLoadIpsecDispatch(XPCH_CLIENT *Client, FE_IPSEC_DISPATCH *Dispatch);
BOOL FePrintIpsecDispatch(XPCH_CLIENT *Client);
BOOL FeLoadIpfDispatch(XPCH_CLIENT *Client, FE_IPF_DISPATCH *Dispatch);
BOOL FePrintIpfDispatch(XPCH_CLIENT *Client);
BOOL FePrintTdiCallbacks(XPCH_CLIENT *Client);
BOOL FePrintTdiPnpClients(XPCH_CLIENT *Client);
BOOL FePrintNdisOffloadHandlers(XPCH_CLIENT *Client);
BOOL FePrintNdisOidTable(XPCH_CLIENT *Client);
BOOL FePrintNdisInterfaces(XPCH_CLIENT *Client);

#ifdef __cplusplus
}
#endif

#endif /* XPCHUNTER_UM_H */