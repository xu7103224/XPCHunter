# XpchSdk 使用教程

从零开始把一个内核能力 SDK 接进自己的项目。每一步都有可直接复制的代码。

- 版本：1.2.0
- 平台：Windows 10 x64（构建号 18362 实机验证）
- 形态：静态库 `XpchSdk.lib` + 单一头文件 `XpchSdk.h` + 内核驱动 `XPCHunterDrv.sys`

---

## 目录

1. [它能做什么](#1-它能做什么)
2. [交付物清单](#2-交付物清单)
3. [五分钟跑通](#3-五分钟跑通)
4. [在自己的项目里接入](#4-在自己的项目里接入)
5. [接口速查](#5-接口速查)
6. [典型场景代码](#6-典型场景代码)
7. [错误处理](#7-错误处理)
8. [常见问题](#8-常见问题)

---

## 1. 它能做什么

这套 SDK 给你的三环程序提供**内核视角**的能力，全部通过一个已签名的内核驱动完成：

| 能力 | 说明 |
|---|---|
| 进程/线程/模块枚举 | 内核链表遍历，能看到任务管理器看不到的隐藏进程和线程 |
| 进程内存读写 | 可读写受保护进程，不经 `ReadProcessMemory` |
| 内核内存读写 | 读写任意内核地址 |
| 句柄枚举 | 全系统句柄表 |
| 内核模块枚举 | 从驱动自身加载链遍历，不受 psapi 限制 |
| SSDT / Ring3 Hook 扫描 | 检测系统调用表改写和 IAT 劫持 |
| 提权 / 降权 | 调整任意进程 Token 的特权（跨版本兼容） |
| DLL 注入 | 手工映射 PE，不落地、不进 PEB Ldr 链 |
| 签名校验 | Authenticode 内嵌签名 |

**关键设计**：所有基础访问能力都走内核命令，不依赖三环 API。所以对受保护进程、被摘链的隐藏对象同样有效。

---

## 2. 交付物清单

```
build/bin/Release/
├── x64/
│   └── XPCHunterDrv.sys          ← 内核驱动（已签名，需管理员加载）
└── sdk_x64/
    ├── XpchSdk.h                 ← 唯一需要 include 的头文件
    ├── XpchSdk.lib               ← 静态库
    ├── XpchSdkSample.exe         ← 示例程序（演示主要接口）
    ├── XpchSdkTest.exe           ← 逐接口自检（51 条断言）
    └── XpchInjTarget.dll         ← 注入测试用的靶 DLL
```

要交付给别人，只需这四样：`XPCHunterDrv.sys`、`XpchSdk.h`、`XpchSdk.lib`、`XpchSdk接口文档.md`。

---

## 3. 五分钟跑通

### 3.1 加载驱动（管理员权限）

```powershell
# 以管理员身份打开 PowerShell
Unblock-File .\XPCHunterDrv.sys            # 解除下载锁定
sc.exe create XPCHDrv type= kernel binPath= C:\path\to\XPCHunterDrv.sys
sc.exe start XPCHDrv
sc.exe query XPCHDrv                        # 确认 STATE: 4 RUNNING
```

**测试签名要求**（如果驱动未用正式证书签名）：

```powershell
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
bcdedit /set hypervisorlaunchtype off
# 然后重启
```

加载失败返回 577 = 签名验证失败，检查上面三条 bcdedit 并重启。

### 3.2 运行自检

```powershell
cd build\bin\Release\sdk_x64
.\XpchSdkTest.exe
```

正常输出结尾：

```
=== RESULT: PASS 51 / FAIL 0 ===
```

如果这里就失败，先解决问题再往下走——后面所有代码都建立在驱动可用之上。

### 3.3 跑示例

```powershell
.\XpchSdkSample.exe
```

会打印进程列表、内核模块、SSDT hook 检查结果。

---

## 4. 在自己的项目里接入

### 4.1 编译命令

```bat
cl /nologo /W3 /O2 /utf-8 /DUNICODE /D_UNICODE ^
   /I"path\to\sdk_x64" ^
   your_source.c ^
   "path\to\sdk_x64\XpchSdk.lib" ^
   advapi32.lib wintrust.lib crypt32.lib psapi.lib
```

五个链接库缺一不可（`wintrust`/`crypt32` 用于签名校验，`psapi` 用于模块路径，`advapi32` 用于 SCM 枚举）。

`/DUNICODE /D_UNICODE` 建议开启——SDK 的字符串接口都是 UTF-16。

### 4.2 最小程序

```c
#include "XpchSdk.h"
#include <stdio.h>

int main(void)
{
    XPCH_SESSION Session;
    XPCH_STATUS St;
    XPCH_PROCESS_INFO *Procs = NULL;
    ULONG Count = 0, i;

    /* 1. 打开会话（内部完成握手） */
    St = XpchOpen(&Session);
    if (St != XPCH_OK) {
        printf("打开失败: %d\n", St);
        return 1;
    }

    /* 2. 用接口 */
    St = XpchEnumProcesses(&Session, &Procs, &Count);
    if (St == XPCH_OK) {
        printf("共 %lu 个进程\n", Count);
        for (i = 0; i < Count; i++)
            printf("  PID %-6lu %s\n", Procs[i].Pid, Procs[i].Name);
        XpchFree(Procs);            /* 必须用 XpchFree 释放 */
    }

    /* 3. 关闭 */
    XpchClose(&Session);
    return 0;
}
```

### 4.3 三条铁律

1. **所有返回指针的接口，都用 `XpchFree` 释放**，不要用 `free` / `HeapFree`。
2. **`XPCH_SESSION` 可以栈上分配，但必须先 `XpchOpen` 初始化**。
3. **返回值 0 = 成功**，负数才是错误。判断用 `if (St != XPCH_OK)` 或 `if (St < 0)`。

---

## 5. 接口速查

### 生命周期

| 接口 | 用途 |
|---|---|
| `XpchOpen(&s)` | 打开会话并握手 |
| `XpchClose(&s)` | 关闭 |
| `XpchProbe()` | 只探测驱动是否可用，不建会话 |
| `XpchGetBuildNumber(&s, &n)` | 取驱动报告的 Windows 构建号 |

### 枚举

| 接口 | 返回 |
|---|---|
| `XpchEnumProcesses(&s, &procs, &n)` | PID / EPROCESS 地址 / 映像名 |
| `XpchEnumThreads(&s, pid, &ts, &n)` | TID / 起始地址 / Teb / 优先级 |
| `XpchEnumModules(&s, pid, &ms, &n)` | 模块基址 / 大小 / 名 / 完整路径 |
| `XpchEnumSystemHandles(&s, &hs, &n)` | 全系统句柄表 |
| `XpchEnumKernelModules(&s, &km, &n)` | 内核模块基址 / 名 / 路径 |
| `XpchEnumDrivers(&ds, &n)` | SCM 注册的驱动服务 |
| `XpchEnumHiddenDrivers(&s, &hd, &n)` | 已加载但 SCM 没有的（隐藏驱动） |
| `XpchEnumSsdtHooks(&s, &e, &n)` | 两张系统调用表全部条目及改写标志 |
| `XpchScanProcessHooks(&s, pid, &h, &n)` | 进程内 IAT 劫持 + inline patch |

### 内存

| 接口 | 说明 |
|---|---|
| `XpchReadProcessMemory(&s, pid, addr, size, &buf, &got)` | 读进程内存（MmCopyVirtualMemory） |
| `XpchReadKernelMemory(&s, addr, size, &buf, &got)` | 读内核内存（逐页安全拷贝） |
| `XpchWriteProcessMemory(&s, pid, addr, data, size)` | ⚠ 写进程内存 |
| `XpchWriteKernelMemory(&s, addr, data, size)` | ⚠ 写内核内存，可绕只读页 |

### 特权与注入

| 接口 | 说明 |
|---|---|
| `XpchAdjustProcessPrivileges(&s, pid, op, &total, &enabled)` | `XPCH_PRIV_QUERY` / `ENABLE_ALL` / `DISABLE_ALL` |
| `XpchInjectDll(&s, pid, path, flags, &base)` | 手工映射 DLL |

### 工具

| 接口 | 说明 |
|---|---|
| `XpchFree(p)` | 释放 SDK 分配的内存 |
| `XpchStatusText(st)` | 状态码转可读文字（返回静态串，不要 free） |
| `XpchUtf16ToAnsi(w, a, n)` | UTF-16 → ANSI |
| `XpchVerifyFileSignature(path, &state)` | 校验文件 Authenticode 签名 |

---

## 6. 典型场景代码

### 6.1 找出隐藏进程

内核进程链表 vs 三环可见进程，差集就是隐藏的：

```c
/* 内核视角全集 */
XPCH_PROCESS_INFO *Kernel = NULL;
ULONG KN = 0, i;
XpchEnumProcesses(&S, &Kernel, &KN);

/* 三环视角：用 Toolhelp 建集合 */
HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32W Pe = { sizeof(Pe) };
if (Process32FirstW(Snap, &Pe)) {
    do {
        BOOL Found = FALSE;
        for (i = 0; i < KN; i++) {
            if (Kernel[i].Pid == Pe.th32ProcessID) { Found = TRUE; break; }
        }
        if (!Found)
            wprintf(L"内核有、三环无: PID %lu %s\n", Pe.th32ProcessID, Pe.szExeFile);
    } while (Process32NextW(Snap, &Pe));
}
CloseHandle(Snap);
XpchFree(Kernel);
```

### 6.2 读受保护进程的内存

```c
BYTE *Buf = NULL;
ULONG Got = 0;
XPCH_STATUS St = XpchReadProcessMemory(&S, TargetPid, 0x401000, 0x100, &Buf, &Got);
if (St == XPCH_OK) {
    /* Buf 有效，Got == 0x100 */
    XpchFree(Buf);
}
```

### 6.3 检测 SSDT Hook

```c
XPCH_SSDT_ENTRY *E = NULL;
ULONG N = 0, i;
if (XpchEnumSsdtHooks(&S, &E, &N) == XPCH_OK) {
    for (i = 0; i < N; i++) {
        if (E[i].AddressPatched)
            printf("SSDT[%lu] 表项被改写: %llx -> %llx\n",
                   E[i].Index, E[i].Original, E[i].Current);
        if (E[i].BytesPatched)
            printf("SSDT[%lu] 函数体被 inline patch\n", E[i].Index);
    }
    XpchFree(E);
}
```

### 6.4 找一个没有签名的内核模块

```c
XPCH_KERNEL_MODULE *Km = NULL;
ULONG N = 0, i;
XpchEnumKernelModules(&S, &Km, &N);

for (i = 0; i < N; i++) {
    XPCH_SIGNATURE_STATE Sig;
    WCHAR Path[MAX_PATH];
    /* Km[i].Path 是 ANSI，转宽字符 */
    MultiByteToWideChar(CP_ACP, 0, Km[i].Path, -1, Path, MAX_PATH);
    if (XpchVerifyFileSignature(Path, &Sig) == XPCH_OK
        && Sig != XPCH_SIG_VALID) {
        printf("未签名/签名无效: %s\n", Km[i].Name);
    }
}
XpchFree(Km);
```

### 6.5 提权 / 降权

```c
ULONG Total = 0, Enabled = 0;

/* 查询当前状态 */
XpchAdjustProcessPrivileges(&S, Pid, XPCH_PRIV_QUERY, &Total, &Enabled);
printf("共 %lu 个特权，已启用 %lu 个\n", Total, Enabled);

/* 全部启用（提权） */
XpchAdjustProcessPrivileges(&S, Pid, XPCH_PRIV_ENABLE_ALL, NULL, &Enabled);
printf("启用后: %lu\n", Enabled);      /* == Total */

/* 全部禁用（降权） */
XpchAdjustProcessPrivileges(&S, Pid, XPCH_PRIV_DISABLE_ALL, NULL, &Enabled);
printf("禁用后: %lu\n", Enabled);      /* == 0 */
```

实现只用导出 API、零结构偏移，所以换 Windows 版本不用改代码。

### 6.6 注入 DLL（手工映射）

```c
ULONG64 RemoteBase = 0;
XPCH_STATUS St = XpchInjectDll(&S, TargetPid,
                               L"C:\\path\\to\\payload.dll",
                               0,               /* 0 = 映射后调用 DllMain */
                               &RemoteBase);
if (St == XPCH_OK)
    printf("已映射到 %llx\n", RemoteBase);
```

只映射不执行：

```c
XpchInjectDll(&S, Pid, DllPath, XPCH_INJECT_NORUN, &Base);
```

注入后想确认 DllMain 真的跑了，可以读回 DLL 里的某个标记变量：

```c
BYTE *Mem = NULL;
ULONG Got = 0;
Sleep(1500);      /* 远程线程是异步的，等它跑完 */
XpchReadProcessMemory(&S, Pid, RemoteBase + 0x3000, 8, &Mem, &Got);
/* 检查 Mem 里的值是否等于你的标记 */
```

**注入的硬性限制**（必须知道）：

- 只支持 x64 DLL，目标必须是 x64 进程
- 依赖的 DLL 必须**已经**在目标进程里加载（不做递归装载）
- 不处理 TLS 回调
- 映射结果不进 PEB Ldr 链，`XpchEnumModules` 看不到（这是 manual map 的固有特性）
- 别对 Session 0 的进程做注入：手工映射缺 CRT/TLS 初始化，在那种环境容易触发 0x3B

---

## 7. 错误处理

```c
XPCH_STATUS St = XpchEnumProcesses(&S, &P, &N);
if (St != XPCH_OK) {
    char A[128];
    XpchUtf16ToAnsi(XpchStatusText(St), A, sizeof(A));
    fprintf(stderr, "失败: %d (%s)\n", St, A);
}
```

常见错误码：

| 码 | 值 | 含义 | 怎么办 |
|---|---|---|---|
| `XPCH_OK` | 0 | 成功 | — |
| `XPCH_E_NO_DEVICE` | -1 | 打不开设备 | 驱动没加载，或不是管理员 |
| `XPCH_E_NOT_OPENED` | -2 | 会话未打开 | 先调 `XpchOpen` |
| `XPCH_E_HANDSHAKE` | -3 | 握手失败 | 驱动版本不匹配 |
| `XPCH_E_IOCTL` | -4 | IOCTL 失败 | ioctl 码问题，驱动版本不对 |
| `XPCH_E_REJECTED` | -5 | 驱动拒绝 | 看文档"10 个拒绝点" |
| `XPCH_E_INVALID_ARG` | -6 | 参数非法 | 检查入参 |
| `XPCH_E_NOT_FOUND` | -7 | 目标不存在 | 进程/文件没找到 |
| `XPCH_E_NO_DATA` | -8 | 空结果 | 枚举结果为空 |
| `XPCH_E_NOT_SUPPORTED` | -13 | 当前版本不支持 | 比如非 18362 构建跑线程枚举 |

**`XPCH_E_NOT_SUPPORTED` 的典型来源**：`XpchEnumThreads` / `XpchEnumModules` 依赖的内核结构偏移是 Win10 18362 实机核实的。其它构建号会直接返回这个码，而不会错位解析出垃圾数据。

---

## 8. 常见问题

**Q：必须管理员权限吗？**

绝大多数接口是。枚举进程、驱动服务之外的都要驱动，而打开设备句柄需要管理员。`XpchEnumDrivers` 和 `XpchVerifyFileSignature` 是纯用户态，不需要。

**Q：能在 32 位程序里用吗？**

SDK 是 x64 静态库，32 位程序链接不了。如果主程序是 32 位，把这部分能力做成独立的 64 位辅助进程，用 IPC 调用。

**Q：多线程安全吗？**

每个 `XPCH_SESSION` 内部串行化，不同会话可以并行。但驱动侧是全局串行的，实际请求仍然排队。耗时的接口（`XpchScanProcessHooks`）别放 UI 线程。

**Q：调用返回 -5（REJECTED）但驱动明明在跑？**

说明请求到了驱动但被拒绝。最常见是握手没成功。先调 `XpchProbe()` 确认驱动就绪；如果 Probe 成功而具体接口被拒，检查参数长度——每条命令对 InputSize/OutputSize 有精确要求。

**Q：注入返回成功，但目标进程崩了？**

如果你自己改造过注入流程，检查两点：远程线程入口执行完必须 `RtlExitUserThread(0)`，不能直接 return；起始地址必须落在目标进程已映射的可执行页上。

**Q：线程/模块枚举返回 NOT_SUPPORTED？**

当前构建号不是 18362。这两个接口的偏移表是硬核实过的，不做猜测性解析。要支持其它版本需要补偏移表。

**Q：写完内核内存蓝屏了？**

`XpchWriteKernelMemory` 不做任何目标校验。写错地址立即蓝屏，这是预期行为。写之前务必确认地址和内容都正确。

---

## 附：验证自己的接入是否成功

把 `XpchSdkTest.exe` 的逻辑当成验收清单。你自己的程序至少要能跑通这一段：

```c
XPCH_SESSION S;
assert(XpchOpen(&S) == XPCH_OK);              /* 驱动可用 */

ULONG Build = 0;
assert(XpchGetBuildNumber(&S, &Build) == XPCH_OK);

XPCH_PROCESS_INFO *P = NULL;
ULONG N = 0;
assert(XpchEnumProcesses(&S, &P, &N) == XPCH_OK && N > 0);
XpchFree(P);

assert(XpchProbe() == XPCH_OK);
XpchClose(&S);
```

这四条过了，说明驱动、握手、协议、内存分配都正常，剩下的接口只是数据不同。