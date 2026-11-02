# XpchSdk 接口文档

面向第三方项目的内核能力 SDK。

- 版本：1.1.0
- 形态：静态库 `XpchSdk.lib` + 单一头文件 `XpchSdk.h`
- 依赖：运行期需要 `XPCHunterDrv.sys` 已加载（部分纯用户态接口除外，见 §7）
- 能力范围：以只读为主，另含四个写原语（§5.12，破坏性能力，调用方对后果负责）；
  不含杀进程、卸载驱动、改系统表
- 实现原则：**全部基础访问能力经内核命令完成，不回退三环 API**
  （内存读写 0x023/0x081、内核读写 0x099/0x082、进程/线程/模块遍历
  SDK 侧经内核读完成）

---

## 1. 快速开始

### 1.1 编译链接

```bat
:: 1) 构建 SDK（在仓库根执行）
build\build_sdk.bat

:: 产物
::   build\bin\Release\sdk_x64\XpchSdk.lib
::   build\bin\Release\sdk_x64\XpchSdk.h
```

在自己的项目里：

```bat
cl /utf-8 /I<path>\sdk_x64 myapp.c ^
   <path>\sdk_x64\XpchSdk.lib ^
   advapi32.lib wintrust.lib crypt32.lib psapi.lib
```

需要链接的库：
`advapi32`（SCM）、`wintrust` + `crypt32`（签名校验）、`psapi`（模块枚举）。

### 1.2 最小示例

```c
#include "XpchSdk.h"
#include <stdio.h>

int main(void)
{
    XPCH_SESSION S;
    XPCH_PROCESS_INFO *Procs;
    ULONG N, i;

    if (XpchOpen(&S) != XPCH_OK) {
        wprintf(L"驱动未就绪: %s\n", XpchStatusText(XpchProbe()));
        return 1;
    }

    if (XpchEnumProcesses(&S, &Procs, &N) == XPCH_OK) {
        for (i = 0; i < N; i++)
            printf("%-6lu %s\n", Procs[i].Pid, Procs[i].Name);
        XpchFree(Procs);           /* 必须用 XpchFree，不能用 free/HeapFree */
    }

    XpchClose(&S);
    return 0;
}
```

---

## 2. 生命周期

```
XpchOpen()  →  若干业务调用  →  XpchClose()
```

`XpchOpen` 内部完成三件事：

1. 打开设备 `\\.\View++ByLinxer`
2. 由设备名派生 ioctl 码（`0x05E00158`）与密钥字节（`0xCF`）
3. **握手**：向驱动发 0x22 许可包，使 `GT[0x304]` 置位

第 3 步很关键。驱动在就绪标志为 0 时**只放行 0x22**，其余命令一律被拒。
所以如果不握手，除 `XpchProbe`/`XpchOpen` 外的所有接口都会返回 `XPCH_E_REJECTED`。

`XPCH_SESSION` 可以栈上分配，但必须用 `XpchOpen` 初始化、`XpchClose` 释放。
结构体内部字段不透明，不要直接读写。

---

## 3. 错误处理

所有接口返回 `XPCH_STATUS`。`XPCH_OK == 0`，其余为负值。

| 状态码 | 含义 | 常见原因 |
|---|---|---|
| `XPCH_OK` | 成功 | |
| `XPCH_E_NO_DEVICE` | 打不开设备 | 驱动未加载；或进程权限不足 |
| `XPCH_E_NOT_OPENED` | 会话未打开 | 忘记调 `XpchOpen`，或已 `XpchClose` |
| `XPCH_E_HANDSHAKE` | 握手失败 | 驱动未完成初始化；或驱动版本不匹配 |
| `XPCH_E_IOCTL` | ioctl 本身失败 | 设备被关闭；ioctl 码不匹配 |
| `XPCH_E_REJECTED` | 驱动拒绝 | 见下文的"10 个拒绝点" |
| `XPCH_E_INVALID_ARG` | 参数非法 | 空指针、长度为 0、PID 为 0 |
| `XPCH_E_NOT_FOUND` | 目标不存在 | 文件路径不存在 |
| `XPCH_E_ACCESS_DENIED` | 无访问权限 | 受保护进程；OpenProcess 失败 |
| `XPCH_E_BUFFER_TOO_SMALL` | 缓冲区不足 | 路径缓冲小于要求 |
| `XPCH_E_NO_DATA` | 空结果 | 表为空、无匹配项 |
| `XPCH_E_BAD_RESPONSE` | 输出结构异常 | 驱动版本差异导致布局变化 |
| `XPCH_E_NO_MEMORY` | 本地分配失败 | |
| `XPCH_E_NOT_SUPPORTED` | 能力不支持 | 当前 Windows/驱动版本 |
| `XPCH_E_PARTIAL` | 部分成功 | 已返回能取到的部分数据 |

`XpchStatusText()` 返回对应中文描述（静态字符串，不要 free）。

### 关于 `XPCH_E_REJECTED`

驱动收到请求后，无论成功失败，`DeviceIoControl` 都返回成功 —— 它的
`IoStatus.Status` 恒为 `STATUS_SUCCESS`。真正的结果写在请求里
`ResultBytePtr` 指向的 1 字节：

- `1` = 处理器执行且返回成功
- `0` = 请求被拒

驱动有 10 个拒绝点：输入长度非 0x30、ioctl 不匹配、Magic 错、MD5 校验错、
指针越界、命令号越界、驱动未就绪、进程访问校验失败、命令槽为空、重入锁冲突。
SDK 把这些统一映射为 `XPCH_E_REJECTED`。

注意：**部分命令成功时也返回 0**（如句柄枚举）。SDK 内部对这类命令改用
"输出结构是否合理"判定，调用方无需关心。

---

## 4. 内存管理

所有返回指针的接口，其内存都由 SDK 的进程堆分配。**必须用 `XpchFree` 释放**，
不能用 `free` / `HeapFree` / `delete` —— 堆句柄不同会崩溃。

```c
XPCH_PROCESS_INFO *P = NULL;
ULONG N = 0;
if (XpchEnumProcesses(&S, &P, &N) == XPCH_OK) {
    /* ... 使用 ... */
}
XpchFree(P);        /* 即使 N == 0 也要调（内部检查 NULL） */
```

---

## 5. 接口参考

### 5.1 会话

```c
XPCH_STATUS XpchOpen(XPCH_SESSION *Session);
void        XpchClose(XPCH_SESSION *Session);
XPCH_STATUS XpchProbe(void);
XPCH_STATUS XpchGetBuildNumber(XPCH_SESSION *Session, ULONG *BuildNumber);
```

| 接口 | 说明 |
|---|---|
| `XpchOpen` | 打开会话并握手。重复调用安全（会先关旧句柄） |
| `XpchClose` | 关闭会话。传 NULL 安全 |
| `XpchProbe` | 只探测驱动是否可用，不建立长期会话 |
| `XpchGetBuildNumber` | 取驱动报告的 Windows 构建号（如 18362） |

`XpchGetBuildNumber` 返回的是**驱动当前运行的系统版本**，不是编译 SDK 时的版本。
跨版本使用时可以据此选择不同的解析路径。

---

### 5.2 进程

```c
typedef struct _XPCH_PROCESS_INFO {
    ULONG   Pid;
    ULONG64 Eprocess;                     /* EPROCESS 内核地址 */
    char    Name[16];                     /* 映像名，如 "explorer.exe" */
} XPCH_PROCESS_INFO;

XPCH_STATUS XpchEnumProcesses(XPCH_SESSION *Session,
                              XPCH_PROCESS_INFO **Processes, ULONG *Count);
XPCH_STATUS XpchGetProcessPath(XPCH_SESSION *Session, ULONG Pid,
                               WCHAR *Path, ULONG PathChars);
XPCH_STATUS XpchIsProcessAccessible(XPCH_SESSION *Session, ULONG Pid,
                                    BOOL *Accessible);
```

**`XpchEnumProcesses`**

返回驱动视角的完整进程链表，包括仅内核可见的进程（`csrss`/`smss` 等）。
本机实测约 179 条。

- `Name` 最长 15 字符 —— 受 `EPROCESS.ImageFileName` 字段长度限制
- 不返回路径（要路径用 `XpchGetProcessPath`，但那是逐进程查询）
- 结果需 `XpchFree`

**`XpchGetProcessPath`**

`Path` 必须是 `XPCH_PROC_PATH_CHARS`(520) 字符的缓冲。
对 PID 0/4 这类系统进程，返回 `XPCH_OK` 但 `Path` 是空串 —— 它们没有用户态映像。

**`XpchIsProcessAccessible`** —— ⚠️ **语义有限，不建议依赖**

底层是 0x27 `CmdCheckProcessAccess`。这个名字容易误解：它在原版里**不是**
"可访问性查询"，而是"能否对该进程**解除保护**"的前置判定 —— 判定失败时
内部会调用 `ProcessOperationWithAttach`（附加到目标进程、清保护标志、
调整页表），是**写入型**操作。

因此对绝大多数普通进程它本就返回 0。实测对照：

| 进程 | 返回 |
|---|---|
| 不存在的 PID | 1（异常：驱动把 NULL 与 NULL 判等） |
| 自身进程 | 0 |
| System / Registry | 0 |

第一条尤其反直觉 —— 传一个不存在的 PID 反而"可访问"。根因是驱动的
`CheckProcessAccess` 拿 `GT[0x185]`（由 0x20 写入 `IoGetCurrentProcess`，
即驱动所在系统进程）与目标比较，两者都是 NULL 时判等成立。

**这个接口保留只为完整性，不建议用它判断"能不能操作某进程"。**
正确的做法是直接 `OpenProcess` 看返回值：

```c
HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
BOOL Accessible = (h != NULL);
if (h) CloseHandle(h);
```

---

### 5.3 线程

```c
typedef struct _XPCH_THREAD_INFO {
    ULONG   Tid;
    ULONG   OwnerPid;
    ULONG   BasePriority;
    ULONG   DeltaPriority;
    ULONG64 StartAddress;
    ULONG64 KernelStack;
    ULONG64 Teb;
} XPCH_THREAD_INFO;

XPCH_STATUS XpchEnumThreads(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_THREAD_INFO **Threads, ULONG *Count);
```

**数据源说明**：SDK 侧遍历 `EPROCESS → ThreadListHead → ETHREAD`，
内核字段经 0x099 内核读逐次获取；**驱动全程不做用户态内存访问**，
单次读失败仅返回错误码，不会蓝屏。所有偏移量为 Win10 18362 x64
实机 `dt` 核实值（`KPROCESS.ThreadListHead=0x30`、
`KTHREAD.ThreadListEntry=0x2F8`、`ETHREAD.Cid=0x648`、
`ETHREAD.Win32StartAddress=0x6A0`、`KTHREAD.Teb=0xF0`、
`KTHREAD.BasePriority=0x233`）。

填充字段：`Tid` / `OwnerPid` / `StartAddress`（Win32StartAddress）/
`Teb` / `BasePriority`；`DeltaPriority` / `KernelStack` 恒为 0。
其它 Windows 版本返回 `XPCH_E_NOT_SUPPORTED`（偏移表按构建扩展）。

---

### 5.4 模块

```c
typedef struct _XPCH_MODULE_INFO {
    ULONG64 Base;
    ULONG64 Size;
    WCHAR   Name[64];
    WCHAR   Path[520];
} XPCH_MODULE_INFO;

XPCH_STATUS XpchEnumModules(XPCH_SESSION *Session, ULONG Pid,
                            XPCH_MODULE_INFO **Modules, ULONG *Count);
```

枚举进程内已加载的 DLL/EXE。SDK 侧遍历
`EPROCESS → PEB → Ldr → InLoadOrderModuleList`：`EPROCESS.Peb`（0x3F8）
经 0x099 内核读，Ldr 链（`PEB.Ldr=0x18`、`InLoadOrderModuleList=0x10`、
`DllBase=0x30`、`SizeOfImage=0x40`、`BaseDllName=0x58`）是目标进程
用户内存，经 0x023 进程读逐次获取——每步都是独立安全读，
**不依赖目标进程可访问**，受保护进程同样可枚举（内核视角）。

其它 Windows 版本返回 `XPCH_E_NOT_SUPPORTED`（偏移表按构建扩展）。

---

### 5.5 句柄

```c
typedef struct _XPCH_HANDLE_INFO {
    ULONG   Pid;
    ULONG   HandleIndex;          /* 当前命令不提供，恒为 0 */
    ULONG   ObjectTypeIndex;      /* 恒为 0 */
    ULONG   GrantedAccess;        /* 恒为 0 */
    ULONG64 Object;
    WCHAR   TypeName[64];         /* 恒为空 */
} XPCH_HANDLE_INFO;

XPCH_STATUS XpchEnumSystemHandles(XPCH_SESSION *Session,
                                  XPCH_HANDLE_INFO **Handles, ULONG *Count);
```

**能力限制（重要）**：0x26 命令虽然叫 `CmdEnumHandles`，实际输出是
**进程记录**（552 字节/条）而非逐句柄列表。所以本接口只填 `Pid` 和 `Object`
（进程对象地址），其余字段为 0。

如果需要逐句柄枚举（每个进程开了哪些句柄），请用 Win32 的
`NtQuerySystemInformation(SystemHandleInformation)` 自行实现 ——
这不需要驱动。

---

### 5.6 内核模块与驱动

```c
typedef struct _XPCH_KERNEL_MODULE {
    ULONG64 Base;
    ULONG64 Size;                  /* 相邻基址差值推算，最后一项为 0 */
    char    Name[64];
    char    Path[320];
} XPCH_KERNEL_MODULE;

XPCH_STATUS XpchEnumKernelModules(XPCH_KERNEL_MODULE **Modules, ULONG *Count);

typedef struct _XPCH_DRIVER_INFO {
    char    Name[128];             /* 服务名 */
    char    Display[160];          /* 显示名 */
    char    Path[320];             /* ImagePath */
    DWORD   State;                 /* SERVICE_RUNNING 等 */
    DWORD   Start;                 /* SERVICE_BOOT_START 等 */
    DWORD   Type;                  /* SERVICE_KERNEL_DRIVER 等 */
} XPCH_DRIVER_INFO;

XPCH_STATUS XpchEnumDrivers(XPCH_DRIVER_INFO **Drivers, ULONG *Count);

XPCH_STATUS XpchEnumHiddenDrivers(XPCH_SESSION *Session,
                                  XPCH_KERNEL_MODULE **Hidden, ULONG *Count);
```

两个枚举都**不需要驱动**：内核模块走 `EnumDeviceDrivers`，驱动服务走 SCM。

`Size` 是推算值 —— psapi 只给基址，SDK 按基址排序后用相邻差值估算，
最后一项无法推算所以记 0。

**`XpchEnumHiddenDrivers`** 是推导接口：取"内核模块列表"与"驱动服务列表"
的差集。判定依据是模块名能否在服务名或 ImagePath 里找到。

⚠️ **这个接口有误报**。临时加载又卸载的驱动、以及 Windows 自带的某些
内核组件（如 `kdnet.dll`、`mcupdate_*.dll`）没有对应的服务项，
会被报成"隐藏"。**必须人工复核**，不要直接当恶意驱动处理。

---

### 5.7 SSDT / Ring0 Hook

```c
typedef struct _XPCH_SSDT_ENTRY {
    ULONG   TableIndex;         /* 1 = SSDT，2 = Shadow SSDT */
    ULONG   Index;              /* 表内索引（syscall 号） */
    ULONG64 Current;            /* 当前地址 */
    ULONG64 Original;           /* 磁盘原始地址 */
    BOOL    AddressPatched;     /* 表项被改写 */
    BOOL    BytesPatched;       /* 函数前 16 字节被改（inline patch） */
    BYTE    OriginalBytes[16];  /* 磁盘原始指令 */
    char    Disasm[96];         /* 原始指令的助记符 */
} XPCH_SSDT_ENTRY;

XPCH_STATUS XpchEnumSsdtHooks(XPCH_SESSION *Session,
                              XPCH_SSDT_ENTRY **Entries, ULONG *Count);
```

返回两张系统调用表的全部条目。Win10 18362 上实测 908 条（454 + 454）。

**这是检测内核 hook 的主要接口**。用法：

```c
XPCH_SSDT_ENTRY *E; ULONG N, i, Patched = 0;
if (XpchEnumSsdtHooks(&S, &E, &N) == XPCH_OK) {
    for (i = 0; i < N; i++)
        if (E[i].AddressPatched || E[i].BytesPatched) {
            printf("T%lu[%lu] %s  %016I64X -> %016I64X\n",
                   E[i].TableIndex, E[i].Index,
                   E[i].BytesPatched ? "inline" : "addr",
                   E[i].Original, E[i].Current);
            Patched++;
        }
    XpchFree(E);
}
```

两个标志的区别：

- `AddressPatched`：表的**指针项**被改成别的函数（常见于 SSDT hook）
- `BytesPatched`：**函数体前 16 字节**被改（inline hook / 热补丁）

干净的机器两者都应全为 FALSE。若为 TRUE，`Original` 是原始地址，
`Current` 是被改成的地址，可以据此定位可疑模块。

---

### 5.8 Ring3 Hook

```c
typedef struct _XPCH_RING3_HOOK {
    WCHAR   Owner[64];          /* 发起调用的模块 */
    WCHAR   TargetModule[64];   /* 恒为空 */
    ULONG64 IatAddress;         /* IAT 表项地址 */
    ULONG64 Target;             /* 表项指向的地址 */
} XPCH_RING3_HOOK;

XPCH_STATUS XpchScanProcessHooks(XPCH_SESSION *Session, ULONG Pid,
                                 XPCH_RING3_HOOK **Hooks, ULONG *Count);
```

扫描进程的导入表，找出**指向所有已加载模块之外**的 IAT 表项。

**能力限制**：

- 只做 IAT 检测，不做 inline patch 检测（后者需要读磁盘模块逐字节比对，
  代价高且误报多）
- 只报"完全在模块之外"这种明确可疑的情况。指向**另一个已加载模块**的
  属于正常跨模块导入，不报
- `TargetModule` 恒为空

需要更严格的检测（含 inline patch、同模块 IAT 劫持）时，
参考原工程的 `HookViews.c` 实现。

`Count == 0` 且返回 `XPCH_OK` 表示**没有发现**，不是错误。

---

### 5.9 签名校验

```c
typedef enum _XPCH_SIGNATURE_STATE {
    XPCH_SIG_UNKNOWN  = 0,
    XPCH_SIG_VALID    = 1,    /* 有内嵌签名且信任链完整 */
    XPCH_SIG_INVALID  = 2,    /* 有签名但校验失败 */
    XPCH_SIG_UNSIGNED = 3     /* 无内嵌签名 */
} XPCH_SIGNATURE_STATE;

XPCH_STATUS XpchVerifyFileSignature(const WCHAR *Path,
                                    XPCH_SIGNATURE_STATE *State);
```

走 `WinVerifyTrust`，**不需要驱动**。

**已知限制**：只检查**内嵌签名**，不查系统 catalog。因此 system32 下
部分只靠 catalog 签名的 DLL（如 `uxtheme.dll`）会被报成 `UNSIGNED`。
这是有意为之 —— catalog 检索在离线环境会长时间阻塞，不适合批量调用。
原版行为一致。

---

### 5.10 内存读取

```c
XPCH_STATUS XpchReadProcessMemory(XPCH_SESSION *Session, ULONG Pid,
                                  ULONG64 Address, ULONG Size,
                                  BYTE **Buffer, ULONG *Read);
XPCH_STATUS XpchReadKernelMemory(XPCH_SESSION *Session, ULONG64 Address,
                                 ULONG Size, BYTE **Buffer, ULONG *Read);
```

读目标进程内存（内核 0x023，`MmCopyVirtualMemory` 跨进程拷贝）
与读内核虚拟内存（内核 0x099，逐页 `MmIsAddressValid`+`__try` 安全拷贝，
返回实际读取量）。结果需 `XpchFree`。均可读三环 API 读不到的
进程/地址；读失败只返回错误码，不会蓝屏。

线程/模块枚举（§5.3/§5.4）正是建立在这两条读原语之上。

---

### 5.11 写原语（破坏性能力，谨慎使用）

```c
XPCH_STATUS XpchWriteProcessMemory(XPCH_SESSION *Session, ULONG Pid,
                                   ULONG64 Address, const void *Data, ULONG Size);
XPCH_STATUS XpchWriteKernelMemory(XPCH_SESSION *Session, ULONG64 Address,
                                  const void *Data, ULONG Size);
```

- `XpchWriteProcessMemory`：内核 0x081，`MmCopyVirtualMemory` 反向拷贝，
  可写三环写不到的进程
- `XpchWriteKernelMemory`：内核 0x082，复用驱动的 MDL 物理映射写原语，
  支持只读页绕过

⚠ **调用方对后果负责**：写错地址即蓝屏或破坏系统。SDK 不对写入
目标做任何校验。

---

### 5.12 工具

```c
void XpchFree(void *Memory);
const WCHAR *XpchStatusText(XPCH_STATUS Status);
BOOL XpchUtf16ToAnsi(const WCHAR *Wide, char *Ansi, ULONG AnsiChars);
```

`XpchUtf16ToAnsi` 按 ACP 转换，缓冲不足会返回 FALSE 并写空串。

---

## 6. 典型用法

### 6.1 检测系统是否被 hook

```c
BOOL IsSystemHooked(void)
{
    XPCH_SESSION S;
    XPCH_SSDT_ENTRY *E;
    ULONG N, i;

    if (XpchOpen(&S) != XPCH_OK)
        return FALSE;

    if (XpchEnumSsdtHooks(&S, &E, &N) != XPCH_OK) {
        XpchClose(&S);
        return FALSE;
    }

    for (i = 0; i < N; i++)
        if (E[i].AddressPatched || E[i].BytesPatched) {
            XpchFree(E);
            XpchClose(&S);
            return TRUE;
        }

    XpchFree(E);
    XpchClose(&S);
    return FALSE;
}
```

### 6.2 找出没有签名的内核模块

```c
void ListUnsignedDrivers(void)
{
    XPCH_KERNEL_MODULE *M;
    ULONG N, i;

    if (XpchEnumKernelModules(&M, &N) != XPCH_OK)
        return;

    for (i = 0; i < N; i++) {
        WCHAR Path[MAX_PATH];
        XPCH_SIGNATURE_STATE St;
        /* Path 是 "\SystemRoot\System32\xxx.sys" 这种形式，需展开 */
        if (M[i].Path[0] == '\\' && _strnicmp(M[i].Path, "\\SystemRoot", 11) == 0) {
            WCHAR Sys[MAX_PATH];
            GetSystemWindowsDirectoryW(Sys, MAX_PATH);
            _snwprintf_s(Path, MAX_PATH, _TRUNCATE, L"%s%s", Sys, M[i].Path + 11);
        } else {
            MultiByteToWideChar(CP_ACP, 0, M[i].Path, -1, Path, MAX_PATH);
        }
        if (XpchVerifyFileSignature(Path, &St) == XPCH_OK
            && St != XPCH_SIG_VALID)
            wprintf(L"unsigned: %hs  (%s)\n", M[i].Name, Path);
    }
    XpchFree(M);
}
```

### 6.3 多线程使用

每个线程用独立的 `XPCH_SESSION` 即可：

```c
DWORD WINAPI Worker(LPVOID Param)
{
    XPCH_SESSION S;
    if (XpchOpen(&S) != XPCH_OK)
        return 0;
    /* ... 业务 ... */
    XpchClose(&S);
    return 0;
}
```

注意：驱动内部是**全局串行**的，并发请求会排队。多个会话能并发的只是
用户态准备阶段，实际 IOCTL 仍然串行。耗时命令（`XpchEnumSsdtHooks`、
`XpchScanProcessHooks`）不要放在 UI 线程。

---

## 7. 能力与依赖对照表

| 接口 | 需要驱动 | 需要管理员 | 耗时 |
|---|---|---|---|
| `XpchOpen` / `XpchProbe` | 是 | 是 | 快 |
| `XpchGetBuildNumber` | 是 | 是 | 快 |
| `XpchEnumProcesses` | 是 | 是 | 快（~50ms） |
| `XpchGetProcessPath` | 是 | 是 | 快 |
| `XpchIsProcessAccessible` | 是 | 是 | 快 |
| `XpchEnumThreads` | 是 | 是 | 中（逐字段内核读） |
| `XpchEnumModules` | 是 | 是 | 中（逐字段安全读） |
| `XpchEnumSystemHandles` | 是 | 是 | 中 |
| `XpchEnumKernelModules` | 是 | 是 | 快 |
| `XpchEnumDrivers` | 否 | 是 | 中（逐个查配置） |
| `XpchEnumHiddenDrivers` | 是 | 是 | 中 |
| `XpchEnumSsdtHooks` | 是 | 是 | 中（~200ms） |
| `XpchScanProcessHooks` | 是 | 是 | 慢（1~2s/进程） |
| `XpchVerifyFileSignature` | 否 | 否 | 中（每文件 ~10ms） |
| `XpchReadProcessMemory` | 是 | 是 | 快 |
| `XpchWriteProcessMemory` | 是 | 是 | 快 |
| `XpchReadKernelMemory` | 是 | 是 | 快 |
| `XpchWriteKernelMemory` | 是 | 是 | 快 |

---

## 8. 已知限制与设计取舍

### 8.1 只读

SDK 不封装任何破坏性能力。驱动本身有杀进程（0x28）、写内核内存（0xDB）、
卸载驱动、恢复 SSDT 等命令，但**未暴露**给第三方 —— 这些操作一旦被误用
会直接蓝屏或破坏系统。需要这些能力的场景请自行调用驱动的原始命令，
并自担风险。

### 8.2 结构体布局随 Windows 版本变化

驱动内部多处按构建号分支（如进程列表的 `0xE4` 在不同版本输出布局不同）。
SDK 当前按 Win10 18362 校准。在其他版本上：

- `XpchEnumThreads` / `XpchEnumModules` 因偏移量按构建硬校验，
  直接返回 `XPCH_E_NOT_SUPPORTED`（不会错位解析）
- 其余枚举类接口可能返回 `XPCH_E_BAD_RESPONSE` 或字段错位

建议先用 `XpchGetBuildNumber` 确认版本，再决定是否使用。

### 8.3 不做完整性校验

SDK 不校验驱动二进制本身的签名或版本，不做防篡改。如果驱动被替换，
SDK 会照常工作但结果不可信。需要时请自行校验 `XPCHunterDrv.sys`。

### 8.4 无异步接口

所有接口都是同步阻塞的。需要异步请自行包线程。

---

## 9. 示例程序

`src/sdk/samples/XpchSdkSample.c` 是一个完整示例，
演示打开会话、查构建号、枚举进程/内核模块、查 SSDT hook、读内存。

```bat
build\build_sdk.bat
build\build_sdk_sample.bat
build\bin\Release\sdk_x64\XpchSdkSample.exe
```

在 Win10 18362 guest 上的实测输出：

```
XpchOpen                     : [0] 成功
Windows 构建号               : 18362
XpchEnumProcesses            : [0]   179 processes, first 8:
    PID 4      System
    PID 96     Registry
    PID 324    smss.exe
    ...
XpchEnumKernelModules        : [0]   194 kernel modules, first 5:
    FFFFF8025915D000  hal.dll   \SystemRoot\system32\hal.dll
    FFFFF80259200000  ntoskrnl.exe ...
XpchEnumSsdtHooks            : [0]   908 entries, 0 patched
  (clean, no SSDT hooks)
XpchReadProcessMemory        : [0]   read 64 bytes, first 2 = 4D 5A
```

---

## 10. 逐接口测试

`src/sdk/samples/XpchSdkTest.c` 覆盖全部公开接口与主要错误路径，
共 41 条断言。在 Win10 18362 guest 上实测 **41 PASS / 0 FAIL**
（2026-11-03，驱动 0x0C5 偏移修复后）。

```bat
build\build_sdk.bat
build\build_sdk_sample.bat
build\bin\Release\sdk_x64\XpchSdkTest.exe
```

| 分组 | 覆盖内容 | 结果 |
|---|---|---|
| 工具 | `XpchStatusText` 非空、`XpchUtf16ToAnsi` 正常/缓冲不足/NULL、`XpchFree(NULL)` | 5 PASS |
| 错误路径 | 空指针、未打开会话调用 | 3 PASS |
| 会话 | `XpchProbe`、`XpchOpen`、重复打开、`XpchGetBuildNumber`、关闭后再调 | 5 PASS |
| 进程 | 枚举（含数据校验）、路径、可访问性、模块、线程（校验归属）、Ring3 扫描、读内存（MZ 头 / 无效地址） | 10 PASS |
| 句柄 | 枚举 + 至少一条带 PID | 2 PASS |
| 内核 | 内核模块（含 ntoskrnl）、驱动（路径/运行态已填充）、隐藏驱动 | 5 PASS |
| SSDT | 908 条 + 地址字段全部有效 | 2 PASS |
| 签名 | notepad、不存在路径、NULL | 3 PASS |
| 收尾 | `XpchClose`、关闭后调用 | 2 PASS |

实测数据（2026-11-03，同一台 Win10 18362 guest）：

```
XpchEnumProcesses      146 条
XpchEnumModules        242 个（explorer.exe，SDK 侧 PEB→Ldr 遍历）
XpchEnumThreads        43 个（explorer.exe，SDK 侧 ThreadListHead 遍历）
XpchEnumSystemHandles  125 条
XpchEnumKernelModules  193 个（0x0C5 偏移修复后）
XpchEnumDrivers        384 个（有 ImagePath 373 / 运行中 145）
XpchEnumHiddenDrivers  46 条（含已知误报 ntoskrnl/hal/kdcom 等）
XpchEnumSsdtHooks      908 条，0 条被改写
```

**测试中发现并修正的两个缺陷**（都记在提交信息里）：

1. `XpchIsProcessAccessible` 入参只传了 8 字节，而 0x27 要求 16 字节
   （`{PID, EPROCESS}`），导致处理器直接跳过、恒返回 0。
2. 同一接口把"驱动拒绝"当成了错误返回。实际那是"判定为不可访问"
   的有效结论，现在映射为 `XPCH_OK` + `*Accessible = FALSE`。

第 2 条修完后仍然发现该接口语义本身有问题（见 §5.2 的说明），
最终定性为"不建议依赖"，而不是继续包装成能用的样子。

**2026-11-03 内核化实测的第三个缺陷**：

3. `XpchEnumKernelModules`（0x0C5）读取 `KLDR_DATA_TABLE_ENTRY` 的
   偏移错位 8 字节（`DllBase` 误用 +0x38=EntryPoint、
   `BaseDllName` 误用 +0x68=Flags），此前返回的"模块名"实为
   邻近字段的巧合字节；某个条目的垃圾指针落入用户态后被直接
   解引用，触发 0x3B 蓝屏。已按实机 `dt nt!_KLDR_DATA_TABLE_ENTRY`
   核实修正为 +0x30/+0x40/+0x58/+0x60，并对每个条目补
   `MmIsAddressValid` + `__try` 防护（坏节点即停，带回已收集数据）。

---

## 11. 版本历史

| 版本 | 变更 |
|---|---|
| 1.0.0 | 首个版本。会话/进程/线程/模块/句柄/内核模块/驱动/SSDT/Ring3/签名/读内存 |
| 1.1.0 | ① 全部基础访问能力内核化：读写内存/枚举不再回退三环 API。② 线程、进程模块枚举改为 SDK 侧遍历（EPROCESS→ThreadListHead、EPROCESS→PEB→Ldr，经 0x099/0x023 逐次安全读），删除蓝屏的驱动侧 0x09A/0x09B 命令。③ 修复 0x0C5 KLDR 偏移错位 8 字节导致的蓝屏与假数据。④ 线程/模块偏移量按 Win10 18362 实机 kd 核实，其它构建返回 NOT_SUPPORTED |