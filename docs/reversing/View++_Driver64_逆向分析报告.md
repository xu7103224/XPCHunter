# View++_Driver64.sys 逆向分析报告

## 1. 基本信息

| 属性 | 值 |
|------|-----|
| 文件名 | View++_Driver64.sys |
| 大小 | 689,664 字节 |
| 架构 | x86-64 (AMD64) |
| 文件类型 | Windows 内核驱动 |
| 原始名 | View++_Driver64.pdb (来自 Y:\ViewEngine\Release\) |
| 作者标记 | Linxer (View++ByLinxer) |
| 所属软件 | PCHunter 64位版 |
| MD5 | f778e54132fe131481d59c0d1075f37d |
| SHA256 | d3123ee42bfdbfcb8f625a275ce94f18fc26f9a3bcae13af785c24109a73b7c2 |
| 编译工具 | MSVC (Visual C++) |
| 函数总数 | 1516 |
| 命名函数 | 1502 |
| 库函数 | 14 |
| 已识别字符串 | 98 |

## 2. 总体架构

该驱动是 **PCHunter** 软件的内核驱动程序，提供以下核心功能：

- **进程/线程/模块管理** — 枚举、隐藏检测、强制结束
- **注册表保护与监控** — 注册表操作拦截（SSDT Hook）
- **文件系统监控** — 使用 Minifilter (FLTMGR.SYS) 框架
- **系统内核对象管理** — 对象句柄操作
- **SSDT Hook 引擎** — 系统服务描述符表钩子，含 30 个系统调用挂钩
- **内核模块操作** — 驱动加载/卸载、内存操作
- **进程/线程/对象保护** — 保护指定进程/线程/对象不被结束
- **系统回调引擎** — 各类内核回调注册与处理
- **物理内存/IO 端口操作** — 内存映射、IO 端口读写

### 2.1 内存布局 (Segments)

| 段 | 起始 | 大小 | 权限 | 说明 |
|----|------|------|------|------|
| .text | 0x140001000 | 0x8C000 | RX | 代码段 |
| .rdata | 0x14008D000 | 0x8 | R | 只读数据 |
| .idata | 0x14008D008 | 0x2F0 | R | 导入表 |
| .rdata | 0x14008D2F8 | 0x6D08 | R | 只读数据 |
| .data | 0x140094000 | 0x3A000 | RW | 读写数据 (全局变量表) |
| .pdata | 0x1400CE000 | 0x5000 | R | 异常处理数据 |
| INIT | 0x1400D3000 | 0x1000 | RX | 初始化代码段 (可释放) |

## 3. 内部架构详解

### 3.1 全局变量表 (Global Table) — 核心数据存储

驱动使用一个**全局指针/值数组** `g_GlobalTable[]` 作为核心数据存储机制，通过两个辅助函数访问：

- **`GtRead(index)`** (0x140029EFC) — 读取全局表中索引为 `index` 的值
- **`GtWrite(index, value)`** (0x140029FF4) — 向全局表中索引为 `index` 的位置写入值
- **`GtAlloc(index)`** (0x140029F58) — 分配全局表条目

该数组位于 `.data` 段，包含约 16384 个条目（索引范围从 0 到 0x4000），用于存储：
- 函数指针（命令处理函数表起始于索引 2337）
- 系统内核基地址（NtBuildNumber, ntoskrnl base 等）
- 配置参数
- 运行时状态标志
- 加密密钥
- 回调函数指针

关键索引定义（经验证的数据流追踪结果）：
```
GT_NT_BUILD_NUMBER         0      — InitGtCore: g_GlobalTable[0] = NtBuildNumber
GT_DRIVER_OBJECT           1      — g_DriverObjectPtr 即 g_GlobalTable[1]（地址重叠）
GT_NTOSKRNL_IMAGE_SIZE     2      — InitSdstTable: 写入找到的 ntoskrnl 模块大小
GT_NTOSKRNL_MODULE_BASE    3      — InitSdstTable: 写入找到的 ntoskrnl 模块基址
GT_PATH_BUFFER_00          4      — InitSdstTable: 路径缓冲区 L"\\Sys"
GT_PATH_BUFFER_01          5      — InitSdstTable: 路径缓冲区 L"temR"
GT_PATH_BUFFER_02          6      — InitSdstTable: 路径缓冲区 L"oot\\"
GT_PATH_BUFFER_03          7      — InitSdstTable: 路径缓冲区 L"syst"
GT_PATH_BUFFER_04          8      — InitSdstTable: 路径缓冲区 L"em32"
GT_SYMLINK_BUFFER          9      — InitSdstTable: GtAlloc(9) 分配 0xB0 字节缓冲区
GT_ENCRYPTION_KEY          0x1E0  — 加密密钥
GT_ENCRYPTION_KEY_BYTE     0x1E1  — 加密密钥字节
GT_IRP_BUFFER_SIZE         0x1E2  — IRP 缓冲区大小
GT_GLOBAL_MUTEX            0x1FB  — 全局互斥体
GT_CALLBACK_INITIALIZED    0x354  — 回调初始化标志
GT_CALLBACK_BUSY           0x355  — 回调忙标志
GT_COMMAND_HANDLER_BASE    0x921  — 命令处理函数表基址 (2337)
```

### 3.2 驱动入口 — DriverEntry (0x140080ED4)

```
start → _security_init_cookie → DriverEntry
```

**DriverEntry 执行流程：**

1. **获取 Windows 版本号** — 读取 NtBuildNumber
2. **初始化全局表大小** — 分配 2324 个条目的表空间
3. **保存全局上下文** — 保存 DriverObject、NtBuildNumber、当前进程/线程
4. **生成随机标识** — 使用安全哈希生成随机 Key
5. **解析注册表路径** — 从 RegistryPath 中提取驱动文件所在目录
6. **初始化 SSDT 表解析** — 获取 ntoskrnl.exe 的 SSDT 表地址
7. **读取内核文件** — 从磁盘读取 ntoskrnl.exe 解析 PE 导出表
8. **初始化函数调度表** — 填充命令处理函数索引映射表
9. **解析导出表转发表** — 为每个系统调用建立索引
10. **Windows 版本兼容性检查** — 检查支持的版本列表
11. **初始化子系统** — 注册 Minifilter、初始化 SSDT Hook 引擎
12. **创建设备对象** — 创建 `\Device\View++ByLinxer`
13. **设置 IRP 分发函数** — 注册 Create/Close/DeviceControl 处理
14. **创建符号链接** — `\DosDevices\View++ByLinxer`

**支持的 Windows 版本检查** (IsWindowsVersionSupported, 0x140082658):
- Windows 7: 7600, 7601
- Windows 8: 9200
- Windows 8.1: 9600
- Windows 10: 10240, 10586, 14393, 15063, 16299, 17134, 17763, 18362, 18363, 19041-19045
- Windows Server 2022: 20348
- Windows 11: 22000, 22621, 22631

### 3.3 IRP 分发函数

#### Create/Close Dispatch (0x1400823CC)
```
IRP_MJ_CREATE  → 返回 STATUS_SUCCESS
IRP_MJ_CLOSE   → 返回 STATUS_SUCCESS
```
简单实现，不执行任何特殊操作。

#### Device Control Dispatch (0x1400823EC) — 主 IOCTL 处理

```
IRP_MJ_DEVICE_CONTROL → 复杂分发逻辑
```

处理流程：
1. 验证 `CurrentStackLocation->Parameters.Create.Options == 48` (METHOD_NEITHER)
2. 验证 `MasterIrp` 非空
3. 验证输入缓冲区大小
4. **解密数据** — 使用 XOR 解密算法对 IRP 输入数据进行解密
5. 验证 IRP Type 标记为 `0x20202020`
6. 计算校验和比较
7. **安全检查** — 验证所有用户态指针在 `MmUserProbeAddress` 以下
8. **互斥同步** — 使用 `KeWaitForSingleObject` 和 `Event` 互斥
9. **提取命令号** — 从 IRP 中提取操作码，**命令号 = (opcode - 32 + 2337)**
10. **查表调用** — 从全局表中取出函数指针并调用
11. 返回结果到用户态

**命令分发机制：**
```
handler_index = (opcode - 32) + 2337
handler = global_table[handler_index]  // 函数指针
result = handler(param1, param2, param3, param4)
```

### 3.4 驱动卸载 — DriverUnload (0x140081480)

清理流程：
1. 停止所有监控线程（等待确认退出）
2. 等待全局锁释放（索引 507）
3. 清理 SSDT Hook
4. 注销 Minifilter
5. 释放注册表路径字符串
6. 删除符号链接 `\DosDevices\View++ByLinxer`
7. 删除设备对象

### 3.5 SSDT Hook 引擎 — 核心功能

这是驱动的核心功能。通过解析 ntoskrnl.exe 的 PE 结构，定位系统服务描述符表 (SSDT)，然后挂钩关键系统调用。引擎包含约 50+ 个函数，覆盖从初始化到安装/卸载钩子的完整流程。

#### 初始化流程

**InitSdstTable** (0x140003C3C):
- 两阶段算法：
  - 第一阶段：遍历内核模块链表（`PsLoadedModuleList`），通过检查 NtBuildNumber 和 `::NtBuildNumber` 是否落在模块地址范围内来查找 ntoskrnl.exe
  - 第二阶段：若第一阶段失败，递归扫描模块链表，使用 `ParseNtHeaders` 验证模块名
- 提取模块基址、大小和文件名
- 保存到全局表（GT_NTOSKRNL_BASE, GT_NTOSKRNL_IMAGE_BASE）

**InitSdstServiceCount** (0x140021004):
- 从 SSDT 表中获取系统服务函数总数
- 读取 KiServiceTable 和 KiServiceLimit

**InitSyscallNumberTable** (0x140003FC4):
- 大型函数（~0xFBC 字节）
- 将 ~200 个预计算的 SHA1/CRC 哈希值写入全局表索引 0x415B-0x4479
- 这些哈希值用于运行时系统调用号解析，实现跨 Windows 版本的兼容性

#### 内核文件解析

**ReadNtoskrnlFile** (0x1400051F0):
1. 使用 `ZwOpenFile` 打开 `\SystemRoot\system32\ntoskrnl.exe`
2. 读取文件内容到内存
3. 解析 PE 头（Dos Header → Nt Header → Export Directory）
4. 建立导出函数名 → 地址的映射表

**ParseNtHeaders** (0x140004F80):
- 验证 PE 头部结构（MZ 签名、PE 签名）
- 解析 FILE_HEADER 和 OPTIONAL_HEADER
- 获取节表信息

**ParseNtImageSectionHeaders** (0x1400061B8):
- 遍历所有节表条目
- 识别代码节、数据节、导入节等
- 计算每个节的 RVA 和文件偏移映射

**ParseNtExportDir** (0x140006008):
- 解析导出目录表（Export Directory Table）
- 遍历 AddressOfFunctions、AddressOfNames、AddressOfNameOrdinals
- 建立函数名→序号→RVA 的映射

**GetExportDirSize** (0x140005410):
- 计算导出目录大小
- 通过遍历节表找到包含导出目录的节

**LookupExportFuncAddr** (0x140005448):
- 在导出表中按名称查找函数地址
- 二分查找优化

**BuildExportIndexTable** (0x140005610):
- 解析 PE 导出目录
- 对每个导出函数名计算 SHA1 哈希值
- 存储 (valid_flag=1, hash, ordinal, RVA) 三元组，12 字节每条目
- 用于按名称哈希快速查找导出函数

**ParseNtRelocationTable** (0x1400068AC):
- 附加到目标进程
- 从用户态模块（PEB 加载器数据或 win32k 表）读取重定位表
- 复制模块数据用于服务表构建

**BuildExportServiceTable** (0x1400063E0):
- 调用 ParseNtRelocationTable
- 读取 user32.dll 等模块
- 解析导出目录并构建服务表
- 每个条目包含 9 个字段

**CopyValidServiceEntries** (0x140006800):
- 复制有效的服务表条目
- 过滤无效条目

#### 钩子表构建

**BuildHookTable** (0x140003B3C):
1. 从全局表获取 SSDT 基址和函数数量
2. 解析导出表获得每个函数地址
3. 计算每个函数的 RVA 并存储到转发表
4. 相关索引范围: 16728 ~ 0x447C

#### 系统调用钩子安装与卸载

**InstallHookSyscall** (0x14001C528):
- 安装单个系统调用钩子
- 修改 SSDT 表条目指向钩子函数

**UninstallHookSyscall** (0x14001C8D0):
- 卸载单个系统调用钩子
- 恢复原始 SSDT 表条目

**EnableHookProtection** (0x14001C9FC):
- 启用钩子保护（防止被检测和恢复）

**DisableHookProtection** (0x14001CC4C):
- 禁用钩子保护

#### 30 个 HookSyscallNtXXX 函数

所有 HookSyscallNtXXX 函数遵循统一模式：
1. 从全局表读取偏移量
2. 调用 InitPESectionReadContext + ReadPESectionEntry 循环
3. 扫描特定 PE 节类型/标志
4. 将发现的偏移量写入 GtWrite

完整的挂钩系统调用列表：

| 函数 | 地址 | 大小 |
|------|------|------|
| HookSyscallNtCreateProcess | 0x14001CE20 | 0x112 |
| HookSyscallNtCreateThread | 0x14001CF34 | 0x140 |
| HookSyscallNtOpenProcess | 0x14001D074 | 0x111 |
| HookSyscallNtOpenThread | 0x14001D188 | 0x64 |
| HookSyscallNtOpenKey | 0x14001D4C0 | 0x146 |
| HookSyscallNtOpenKeyEx | 0x14001D608 | 0xFD |
| HookSyscallNtCreateKey | 0x14001D708 | 0x147 |
| HookSyscallNtDeleteKey | 0x14001D850 | 0x134 |
| HookSyscallNtDeleteValueKey | 0x14001D984 | 0xB9 |
| HookSyscallNtSetValueKey | 0x14001DCC0 | 0xEC |
| HookSyscallNtRenameKey | 0x14001DFBC | 0x88 |
| HookSyscallNtCreateFile | 0x14001E5BC | 0xCB |
| HookSyscallNtOpenFile | 0x14001E688 | 0x103 |
| HookSyscallNtReadFile | 0x14001E78C | 0x103 |
| HookSyscallNtWriteFile | 0x14001E890 | 0x115 |
| HookSyscallNtClose | 0x14001ED98 | 0x103 |
| HookSyscallNtDuplicateObject | 0x14001EE9C | 0x103 |
| HookSyscallNtQuerySystemInfo | 0x14001FF5C | 0x147 |
| HookSyscallNtQueryInformationProcess | 0x1400200A4 | 0xFE |
| HookSyscallNtSetInformationProcess | 0x1400201A4 | 0x103 |
| HookSyscallNtQueryInformationThread | 0x1400202A8 | 0x102 |
| HookSyscallNtSetInformationThread | 0x1400203AC | 0x103 |
| HookSyscallNtSuspendProcess | 0x1400204B0 | 0x103 |
| HookSyscallNtResumeProcess | 0x1400205B4 | 0x44 |
| HookSyscallNtSuspendThread | 0x1400205F8 | 0x103 |
| HookSyscallNtResumeThread | 0x1400206FC | 0x103 |
| HookSyscallNtOpenProcessToken | 0x140020800 | 0x64 |
| HookSyscallNtOpenThreadToken | 0x140020BC4 | 0x103 |
| HookSyscallNtCreateToken | 0x140020CC8 | 0x103 |
| HookSyscallNtLoadDriver | 0x140020DCC | 0x238 |

#### 钩子子系统初始化

**InitAllHookSubsystems** (0x14001E9A8):
- 主 SSDT 钩子初始化函数
- 调用 30+ HookSyscallNtXXX 函数
- 根据 NtBuildNumber 进行版本条件初始化
- 覆盖的子系统：进程创建/终止、注册表操作、文件操作、线程操作、Token 操作、驱动加载

#### EPROCESS 字段偏移量初始化

**InitEprocessFieldOffsets** (0x14002131C):
- 版本调度器，根据 NtBuildNumber 分发到版本特定函数
- 支持的版本：Win7, Win8, Win81, Win10 (10240/10586/14393/15063/16299/17134/17763/18362/18363/19041), Win11

版本特定函数列表：
- InitEprocessOffsetsWin7 (0x1400215A4, 0x968 字节)
- InitEprocessOffsetsWin8 (0x1400278FC, 0x86C 字节)
- InitEprocessOffsetsWin81 (0x140026E78, 0xA84 字节)
- InitEprocessOffsetsWin81_Update (0x14002656C, 0x90B 字节)
- InitEprocessOffsetsWin10_10240 (0x140024DDC, 0xA11 字节)
- InitEprocessOffsetsWin10_14393 (0x140021F0C, 0x856 字节)
- InitEprocessOffsetsWin10_15063 (0x140022764, 0xA78 字节)
- InitEprocessOffsetsWin10_17134 (0x1400231DC, 0xA4D 字节)
- InitEprocessOffsetsWin10_18362 (0x140023C2C, 0x87C 字节)
- InitEprocessOffsetsWin10_19041 (0x1400244A8, 0x933 字节)
- InitEprocessOffsetsWin11 (0x1400257F0, 0xD7A 字节)

#### 系统调用号解析

**ResolveSyscallNumbers** (0x140052BF4):
- 根据哈希表匹配系统调用号

**ResolveSyscallNumberTable** (0x140052C1C):
- 解析完整的系统调用号表

**ResolveSyscallNumberFromKernel** (0x140054650):
- 从内核导出表中解析系统调用号

**ResolveSyscallTableEntry** (0x140054AD0):
- 解析单个系统调用表条目

### 3.6 Minifilter 文件系统监控

驱动注册了一个 Minifilter 驱动用于文件系统监控：
- 使用 `FltRegisterFilter` 注册
- 使用 `FltStartFiltering` 启动过滤
- 导入的 FltMgr 函数:
  - FltRegisterFilter / FltUnregisterFilter
  - FltStartFiltering
  - FltGetFileNameInformation / FltReleaseFileNameInformation
  - FltParseFileNameInformation
  - FltCreateFile / FltClose

**InitMiniFilterDriver** (0x140011F6C):
- 初始化 Minifilter 驱动
- 注册 Pre/Post 操作回调

**MiniFilter 回调函数体系**：
- 通过 `SelectMiniFilterCallbackByVersion` (0x140014034) 根据版本选择回调
- 文件操作回调：Create, Read, Write, Cleanup, Close, DirEnum, SetInfo, Delete, Rename, HardLink
- 卷操作回调：VolumeMount, VolumeDismount
- 通信端口回调：CommPortSend, CommPortReply, CommPortConnect, CommPortCleanup
- 上下文回调：ContextCleanup, StreamHandle, NormalizeName, GenerateFileName

### 3.7 加密/解密机制

**通信加密** (DecryptInputBuffer, 0x1400813C0):
- 使用 XOR 加密对 48 字节的 IRP 输入数据进行解密
- 密钥来自全局表索引 481（GT_ENCRYPTION_KEY）的值

**密钥生成** (GenerateEncryptionKey, 0x140029F0C):
- 从注册表路径生成加密密钥

**MD5 哈希** (0x140059CB4 系列):
- 驱动包含标准 MD5 实现
- 使用 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 初始化
- 包含 InitMd5Context, Md5Update, Md5Final, Md5Transform
- 用于校验和/完整性检查

### 3.8 进程/线程/对象保护引擎

驱动实现了三层的保护机制，分别针对进程、线程和内核对象。

#### 进程保护

**EnableProcessProtect** (0x140006BD0):
- 启用进程保护，防止指定进程被结束
- 参数：目标进程地址、标志位、上下文输出、附加参数
- 在进程保护链表中注册受保护进程

**DisableProcessProtect** (0x14000700C):
- 禁用进程保护，从保护链表中移除指定进程

**CheckProcessProtection** (0x140010914):
- 检查指定进程是否受保护
- 在校验过程中验证进程对象有效性

**ProcessCallbackRoutine** (0x140010780):
- 进程创建/终止回调
- 注册 PsSetCreateProcessNotifyRoutine
- 在进程创建时检查是否受保护

**InitProcessCallback** (0x1400106C0):
- 初始化进程回调
- 注册 PsSetCreateProcessNotifyRoutine

#### 线程保护

**EnableThreadProtect** (0x140007AB4):
- 启用线程保护，防止指定线程被终止
- 在线程保护链表中注册受保护线程

**DisableThreadProtect** (0x140007BAC):
- 禁用线程保护，从保护链表中移除指定线程

**ThreadCallbackRoutine** (0x140010A28):
- 线程创建/终止回调
- 注册 PsSetCreateThreadNotifyRoutine

**InitThreadCallback** (0x140010A0C):
- 初始化线程回调

#### 对象保护

**EnableObjectProtect** (0x1400082AC):
- 启用对象保护
- 通过对象类型和名称注册受保护对象

**DisableObjectProtect** (0x140007CC4):
- 禁用对象保护

**DisableObjectProtectEx** (0x140007D54):
- 扩展版禁用对象保护，支持更复杂的解除逻辑

**ObjectPreCallback** (0x14000F894):
- 对象操作前置回调
- 在对象操作前检查是否受保护

**ValidateProcessObject** (0x14004A7AC):
- 验证进程对象有效性
- 包含 30 个局部变量，复杂的状态检查逻辑
- 被 35 个调用者引用

**ValidateProcessContext** (0x14004A044):
- 验证进程上下文

**CheckProtectedEntry** (0x14007A2A0):
- 检查指定条目是否在保护列表中

**WalkObjectTypeList** (0x140007F44):
- 遍历对象类型列表
- 包含 24 个局部变量

#### 对象回调引擎

**InitObjectCallback** (0x14000F0F4):
- 初始化对象回调系统
- 注册 ObRegisterCallbacks

**InitObjectCallbackFiles** (0x14000F8E4):
- 初始化对象回调文件列表（IDA 反编译失败）

**InitObjectCallbackEntries** (0x1400100A4):
- 初始化对象回调条目（IDA 反编译失败）

**EnableObjectCallback** (0x14000FB88):
- 启用对象回调

**DisableObjectCallback** (0x14000FC44):
- 禁用对象回调

**DisableObjectCallbackWithFallback** (0x14000FC14):
- 带回退的禁用对象回调

**DisableObjectCallbackViaDevice** (0x14000FD8C):
- 通过设备对象禁用回调

**InstallObjectPreCallbackHooks** (0x14000FF88):
- 安装对象前置回调钩子

**RestoreObjectPreCallbackHooks** (0x140010020):
- 恢复对象前置回调钩子

**EnableDeviceObjectProtection** (0x140010460):
- 启用设备对象保护

### 3.9 系统回调引擎

驱动注册了多种系统回调，用于监控系统活动。

#### 进程/线程通知

**InitProcessNotify** (0x14001EFA0):
- 初始化进程通知链
- 注册 PsSetCreateProcessNotifyRoutineEx
- 0x941 字节的大型函数

**InitThreadNotify** (0x14001F8E4):
- 初始化线程通知链
- 注册 PsSetCreateThreadNotifyRoutine
- 0x677 字节

#### 镜像加载回调

**InitImageLoadCallback** (0x140010B88):
- 注册 PsSetLoadImageNotifyRoutine

**ImageLoadCallbackRoutine** (0x140010BB0):
- 镜像加载回调处理
- 监控模块加载事件

**InitImageNotify** (0x1400723EC):
- 初始化镜像通知系统
- 调用 24 个子函数

**InitImageNotifyWin7** (0x14001358C):
- Windows 7 特定的镜像通知初始化

**InitImageNotifyCallbackWin7** (0x1400135AC):
- Windows 7 镜像通知回调

#### 注册表回调

**InitRegistryCallback** (0x140010BF8):
- 注册 CmRegisterCallback(Ex)

**RegistryCallbackRoutine** (0x140010C74):
- 注册表回调处理
- 监控注册表操作

#### Bugcheck 回调

**InitBugcheckCallback** (0x140010CCC):
- 注册 KeBugcheckCallback

**BugcheckCallbackRoutine** (0x140010D20):
- Bugcheck 回调处理
- 系统崩溃时执行清理

#### 关机回调

**InitShutdownCallback** (0x140010D68):
- 注册关机回调

**ShutdownCallbackRoutine** (0x140010D90):
- 关机处理

**ShutdownCallbackUnregister** (0x1400118F4):
- 注销关机回调

#### 电源回调

**InitPowerCallback** (0x140010DD4):
- 注册电源回调

**PowerCallbackRoutine** (0x140011240):
- 电源状态变化处理
- 0x3ED 字节

**PowerCallbackUnregister** (0x140011630):
- 注销电源回调
- 0x2C3 字节

#### 文件系统回调

**InitFileSystemCallback** (0x14000D704):
- 初始化文件系统回调

**InitFileSystemFilter** (0x14000EB40):
- 初始化文件系统过滤器

**FileSystemFilterCallback** (0x14000EF84):
- 文件系统过滤器回调

**InitFileSystemFilterCallbacks** (0x14000DC28):
- 初始化文件系统过滤器回调表
- 0x621 字节，包含 90 个基本块

**InitFileSystemExportTable** (0x14000E24C):
- 初始化文件系统导出表

**KernelNotifyRoutine** (0x140019CFC):
- 内核通知例程（2 条指令的 thunk 函数）

**KernelNotifyRoutineEx** (0x140019D04):
- 内核通知扩展例程（2 条指令的 thunk 函数）

### 3.10 内核对象枚举引擎

#### 句柄验证

**ValidateObjReferences** (0x14001C32C):
- 验证对象引用有效性

**ValidateHandleEntry** (0x14006D324):
- 验证单个句柄条目

**ValidateObjectTypeEntries** (0x14006D7D0):
- 验证对象类型条目

**ValidateKernelObject** (0x14004F600):
- 验证内核对象
- 0x3F1 字节

**ValidateAndEnumerateObject** (0x140050078):
- 验证并枚举对象

**ValidateProcessObjectBasic** (0x14004A704):
- 基本进程对象验证

**ValidateProcessObjectEx** (0x14004B398):
- 扩展进程对象验证

**ValidateDriverObjectAddress** (0x14003CD2C):
- 验证驱动对象地址

#### 对象类型枚举

**InitObjectTypeTable** (0x1400837D8):
- 初始化对象类型表

**InitHandleTypeTable** (0x1400853FC):
- 初始化句柄类型表

**ValidateObjectTypeList** (0x14000F788):
- 验证对象类型列表

**EnumObjectTypeFilterCallback** (0x14006CEC8):
- 枚举对象类型过滤器回调

**MatchObjectTypeFilterCallback** (0x14006CDA0):
- 匹配对象类型过滤器回调

**MatchObjectTypeFilterCallbackV2** (0x14006CE34):
- 匹配对象类型过滤器回调 V2

**TraverseHashTableWithCallback** (0x14006D18C):
- 遍历哈希表并调用回调

### 3.11 物理内存/IO 端口/内核内存操作

#### 物理内存操作

**InitPhysicalMemoryContextTable** (0x140034420):
- 初始化物理内存上下文表

**ResolvePhysicalMemoryContext** (0x140033D08):
- 解析物理内存上下文

**CmdCallbackControl** (0x140070190):
- 物理内存回调控制
- 0x834 字节，551 条指令

**ReadWriteCallbackPhysicalMemory** (0x1400709C4):
- 读写物理内存的回调

**ReadCallbackType1/2/3** (0x140070070/0x1400700D0/0x140070130):
- 三种物理内存读取回调类型

**CallbackType1/2/3/4/5Dispatcher** (0x140070B3C 系列):
- 五种物理内存回调分发器

#### IO 端口操作

**ResolveIoPortContext** (0x140037F84):
- 解析 IO 端口上下文

**ValidateIoPortSection** (0x1400389A8):
- 验证 IO 端口节

#### 内核内存操作

**InitKernelDataSectionTable** (0x140066650):
- 初始化内核数据节表

**InitKernelMemoryContext** (0x14006BF2C):
- 初始化内核内存上下文
- 0x300 字节

**InitKernelModuleSectionScan** (0x14006EB48):
- 扫描内核模块节

**InitKernelObjectHeader** (0x14007E034):
- 初始化内核对象头

**ResolveKernelObjectAddresses** (0x140029720):
- 解析内核对象地址

**ResolveKernelModuleBasePair** (0x14002A5C8):
- 解析内核模块基址对

**ResolveKernelModuleIndexAddress** (0x14006E87C):
- 解析内核模块索引地址

**ResolveAndStoreKernelModuleAddress** (0x14006E750):
- 解析并存储内核模块地址

**WriteMemoryValue** / **WriteMemoryBuffer** 系列函数：
- 写入进程内存值/缓冲区

**ValidateZeroPage** (0x14000CFE4):
- 验证零页内存

#### 辅助内存函数

**ExAlloc** (0x140069CEC):
- 内核内存分配包装

**ExFree** (0x140069D58):
- 内核内存释放包装

**CheckMemoryValid** (0x140069DAC):
- 检查内存地址有效性

**GetStringLength** (0x140069E10):
- 获取字符串长度

### 3.12 注册表保护/监控子系统

**InitRegCallback** (0x14000A094):
- 初始化注册表回调

**InitRegNotify** (0x14000C1E0):
- 初始化注册表通知

**InitRegFilter** (0x14000C738):
- 初始化注册表过滤器

**RegNotifyCallback** (0x14000D0B0):
- 注册表通知回调处理
- 0x206 字节

**FindRegCallbackEntry** (0x14000A1A4):
- 查找注册表回调条目

**CmdRegistryProtect** (0x14007E498):
- 注册表保护命令处理

**CmdProtectStatus** (0x14007E32C):
- 保护状态查询命令

### 3.13 命令处理函数表

**InitCommandHandlerTable** (0x1400815B0):
- 初始化命令处理函数调度表
- 0xE1B 字节，535 条指令
- 在全局表索引 2337+ 处填充 ~282 个函数指针
- 命令号与操作码映射：`handler_index = (opcode - 32) + 2337`

命令处理函数覆盖：
- 进程枚举/操作（CmdEnumProcess, CmdTerminateProcess 等）
- 线程枚举/操作（CmdEnumThread, CmdTerminateThread 等）
- 模块枚举（CmdEnumModule, CmdEnumKernelModule 等）
- 注册表操作（CmdRegistryProtect 等）
- 文件系统操作（CmdFileSystemOp 等）
- 驱动操作（CmdDriverProtectOp, CmdDriverProtectStatus 等）
- 对象操作（CmdEnumObjectHandle, CmdEnumObjectType 等）
- 内存操作（CmdReadMemory, CmdWriteMemory 等）
- 回调控制（CmdEnumCallbackContext, CmdSetCallbackContext 等）

### 3.14 模块管理

**InitDriverSection** (0x14003A4F4):
- 初始化驱动节

**InitDriverModuleParsing** (0x140087D80):
- 初始化驱动模块解析

**BuildDriverPathI8042prt** (0x140008914):
- 构建 i8042prt 驱动路径

**BuildDriverPathKbdClass** (0x140008994):
- 构建 kbdclass 驱动路径

**BuildDriverPathMouClass** (0x140008A14):
- 构建 mouclass 驱动路径

**BuildDriversPath** (0x14003A584):
- 构建驱动目录路径

**BuildDriverImagePath** (0x14003A788):
- 构建驱动镜像路径

**BuildSystem32Path** (0x14003A900):
- 构建 System32 路径

**BuildSystemRootPath** (0x140047C50):
- 构建系统根路径

**BuildDevicePath** (0x140047DFC):
- 构建设备路径

**BuildDevicePathFromObjects** (0x14007A410):
- 从对象构建设备路径

**BuildRegistryDriverPath** (0x140045EE4):
- 构建注册表驱动路径

**BuildSyscallDriverPath** (0x140046A80):
- 构建系统调用驱动路径

**LookupDriverObjectEntry** (0x14003AFDC):
- 查找驱动对象条目

**LookupDriverHashTable** (0x140082AF0):
- 查找驱动哈希表

## 4. 导入模块分析

### ntoskrnl.exe 导入

**进程管理:**
- IoGetCurrentProcess, PsLookupProcessByProcessId, PsGetCurrentProcessId, PsLookupThreadByThreadId
- KeStackAttachProcess, KeUnstackDetachProcess
- PsSetCreateProcessNotifyRoutine, PsSetCreateProcessNotifyRoutineEx
- PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine

**文件操作:**
- IoCreateFile, ZwOpenFile, NtFsControlFile, NtDeviceIoControlFile
- IoFileObjectType, MmSectionObjectType

**注册表:**
- ZwCreateKey, ZwSetValueKey, ZwDeleteKey, ZwDeleteValueKey
- ZwEnumerateKey, ZwEnumerateValueKey, ZwQueryKey
- CmRegisterCallback, CmRegisterCallbackEx, CmUnRegisterCallback

**内存管理:**
- MmMapIoSpace, MmUnmapIoSpace, MmMapLockedPagesSpecifyCache, MmUnmapLockedPages
- MmProbeAndLockPages, MmUnlockPages, MmBuildMdlForNonPagedPool
- MmIsAddressValid, MmUserProbeAddress, MmSystemRangeStart
- ExAllocatePool, ExAllocatePoolWithTag, ExAllocatePoolWithQuotaTag, ExFreePoolWithTag

**对象管理:**
- ObReferenceObjectByHandle, ObReferenceObjectByPointer, ObCreateObject, ObOpenObjectByPointer, ObQueryNameString
- ObRegisterCallbacks, ObUnRegisterCallbacks
- SeCreateAccessState

**IRP 操作:**
- IoAllocateIrp, IoAllocateMdl, IoFreeIrp, IoFreeMdl, IofCompleteRequest

**设备操作:**
- IoCreateDevice, IoDeleteDevice, IoCreateSymbolicLink, IoDeleteSymbolicLink
- IoAttachDevice, IoAttachDeviceToDeviceStack, IoAttachDeviceByPointer

**同步:**
- KeInitializeEvent, KeSetEvent, KeWaitForSingleObject
- KeInitializeMutex, KeReleaseMutex
- KeInitializeGuardedMutex, KeAcquireGuardedMutex, KeReleaseGuardedMutex
- KeDelayExecutionThread

**驱动加载:**
- ZwLoadDriver, ZwUnloadDriver
- ZwCreateSection, ZwOpenSection, ZwMapViewOfSection

**其他:**
- RtlInitUnicodeString, RtlAnsiStringToUnicodeString, RtlUnicodeStringToAnsiString
- swprintf, _wcsicmp, wcsncat, wcsrchr, wcscmp, wcsstr
- ProbeForRead, ProbeForWrite
- PsGetVersion, MmGetSystemRoutineAddress
- ExGetPreviousMode, __C_specific_handler
- KeBugCheckEx, KeBugCheck
- KeInitializeDpc, KeInsertQueueDpc

### FLTMGR.SYS 导入
- FltRegisterFilter, FltUnregisterFilter, FltStartFiltering
- FltGetFileNameInformation, FltReleaseFileNameInformation, FltParseFileNameInformation
- FltCreateFile, FltClose
- FltSetCallbackDataDirty, FltPerformCompletionProcessing

### HAL.dll 导入
- HalGetAdapter, HalGetBusDataByOffset, HalAllocateCrashDumpRegisters
- HalTranslateBusAddress, HalReadDmaCounter

## 5. 通信协议

### 用户态 ↔ 内核态通信

1. **设备路径**: `\\.\View++ByLinxer`
2. **IOCTL 方法**: `METHOD_NEITHER`
3. **IOCTL 码格式**: 自定义编码
4. **数据加密**: 48 字节 XOR 加密
5. **命令分发**: 从 IRP 中提取操作码，通过全局函数表查找处理函数

### 命令格式

```
IRP:
  Type              = 0x20202020 (标记)
  AssociatedIrp     = 输入缓冲区指针
  ThreadListEntry   = 用户参数 (Flink/Blink)
  Flags             = 参数1
  MdlAddress        = 结果缓冲区
  Size + 1 处 DWORD = 命令号
```

返回值通过 MdlAddress 的 Next 指针返回。

### 命令处理流程

```
用户态 → DeviceIoControl → 内核态 DispatchDeviceControl
  → 验证 Option == 48
  → 解密输入缓冲区 (XOR)
  → 验证 Type == 0x20202020
  → 验证校验和
  → 互斥锁定
  → handler_index = (Opcode - 32) + 2337
  → global_table[handler_index](Param1, Param2, Param3, Param4)
  → 互斥解锁
  → 返回结果
```

## 6. 关键数据结构

### 全局函数表 (Conceptual)
```c
typedef struct _GLOBAL_TABLE {
    ULONG64 NtBuildNumber;           // [0]     GT_NT_BUILD_NUMBER
    ULONG64 NtoskrnlBase;            // [1]     GT_NTOSKRNL_BASE
    ULONG64 ModuleInfo;              // [2]     GT_MODULE_INFO
    ULONG64 NtoskrnlImageBase;       // [3]     GT_NTOSKRNL_IMAGE_BASE
    ULONG64 CurrentProcess;          // [4]     GT_CURRENT_PROCESS
    ULONG64 CurrentProcessId;        // [5]     GT_CURRENT_PROCESS_ID
    ULONG64 DriverObject;            // [6]     GT_DRIVER_OBJECT
    ULONG64 RegistryPath;            // [7]     GT_REGISTRY_PATH
    ULONG64 DeviceObject;            // [8]     GT_DEVICE_OBJECT
    ULONG64 SymlinkObject;           // [9]     GT_SYMLINK_OBJECT
    // ...
    ULONG64 EncryptionKey;           // [0x1E0] GT_ENCRYPTION_KEY
    ULONG64 EncryptionKeyByte;       // [0x1E1] GT_ENCRYPTION_KEY_BYTE
    ULONG64 IrpBufferSize;           // [0x1E2] GT_IRP_BUFFER_SIZE
    // ...
    ULONG64 GlobalMutex;             // [0x1FB] GT_GLOBAL_MUTEX
    // ...
    ULONG64 CallbackInitialized;     // [0x354] GT_CALLBACK_INITIALIZED
    ULONG64 CallbackBusy;            // [0x355] GT_CALLBACK_BUSY
    // ...
    ULONG64 SyscallHashTable[];      // [0x415B-0x4479] 系统调用哈希表
    // ...
    PVOID  CommandHandlers[];        // [2337]  命令处理函数表
    // ...
} GLOBAL_TABLE, *PGLOBAL_TABLE;
```

### IRP 输入头
```c
typedef struct _IRP_INPUT_HEADER {
    ULONG Type;                     // 必须为 0x20202020
    ULONG Type2;                    // 辅助类型
    ULONG ChecksumHigh;             // 校验和高位
    ULONG ChecksumLow;              // 校验和低位
    ULONG Param1;                   // 参数 1 (Flink)
    ULONG Param2;                   // 参数 2 (Flink high)
    ULONG64 Param3;                 // 参数 3 (UserBuffer1)
    ULONG64 Param4;                 // 参数 4 (UserBuffer2)
    ULONG64 Param5;                 // 参数 5 (MdlAddress)
    ULONG Opcode;                   // 操作码 (Size+1 处)
} IRP_INPUT_HEADER, *PIRP_INPUT_HEADER;
```

### MD5 上下文
```c
typedef struct _MD5_CONTEXT {
    ULONG State[4];                 // 0x00: 状态 (A,B,C,D)
    ULONG Count[2];                 // 0x10: 位计数
    UCHAR Buffer[64];               // 0x18: 数据缓冲区
} MD5_CONTEXT, *PMD5_CONTEXT;
```

## 7. 函数命名组织

所有 1516 个函数已按功能命名，主要分类如下：

| 分类 | 命名前缀 | 函数数量 |
|------|----------|----------|
| 命令处理 | Cmd* | ~282 |
| 钩子安装 | HookSyscall* | 30 |
| 初始化 | Init* | ~80 |
| 解析 | Parse* | ~35 |
| 构建 | Build* | ~30 |
| 验证 | Validate* | ~28 |
| 解析 | Resolve* | ~35 |
| 读取文件 | Read* | ~20 |
| 查找 | Lookup* | 8 |
| 回调 | *Callback* | ~30 |
| 保护 | Enable*/Disable* | 15 |
| 枚举 | Enum* | ~25 |
| 查询 | Query* | ~15 |
| 其他 | 功能命名 | ~900+ |

## 8. 功能总结

PCHunter 驱动实现了以下功能集：

1. **进程管理**: 枚举进程、结束进程、隐藏进程检测、进程保护
2. **线程管理**: 枚举线程、结束线程、线程保护
3. **模块管理**: 枚举内核模块、枚举用户态模块
4. **注册表保护**: 拦截关键注册表操作（创建、删除、枚举、设置值）
5. **文件系统监控**: 通过 Minifilter 监控文件操作
6. **SSDT 钩子**: 系统服务描述符表钩子框架（30 个系统调用挂钩）
7. **内核对象操作**: 对象句柄枚举、对象引用
8. **驱动加载/卸载**: 加载和卸载其他驱动程序
9. **内存操作**: 物理内存映射、IO 端口操作
10. **进程保护**: 保护指定进程不被结束
11. **进程隐藏**: 检测 Rootkit 隐藏进程
12. **系统回调**: 多种内核回调注册（进程、线程、镜像、注册表、电源、关机、Bugcheck）
13. **对象保护**: 保护内核对象不被操作
14. **EPROCESS 偏移量**: 跨 Windows 版本（Win7 ~ Win11 22631）的 EPROCESS 字段偏移量解析

## 9. 全局变量标注

通过函数引用追踪和函数数据操作分析，已完成对 .data 段全局变量的系统标注。

### 9.1 全局变量总览

| 地址 | 名称 | 类型 | 说明 |
|------|------|------|------|
| 0x1400A4088 | __security_cookie | ULONG64 | GS 安全 Cookie |
| 0x1400A4090 | g_BugCheckParam3 | ULONG64 | Bugcheck 回调参数 3 |
| 0x1400A40A0 | g_AesKeyExpanded | int | AES 密钥扩展完成标志 |
| 0x1400A40B0 | g_AesLogTable | BYTE[256] | AES GF(2^8) 对数表 |
| 0x1400A41B0 | g_AesExpTable | BYTE[256] | AES GF(2^8) 指数表 |
| 0x1400A42B0 | g_AesSbox | BYTE[512] | AES S-Box + 逆 S-Box (256+256) |
| 0x1400A44B0 | g_AesRcon | DWORD[10] | AES 轮常数 |
| 0x1400A44E0 | g_AesTe0/1/2/3 | DWORD[256]×4 | AES 加密 T-盒表 (Td0-3) |
| 0x1400A54DC | g_AesTd0/1/2/3 | DWORD[256]×4 | AES 解密 T-盒表 (Td0-3) |
| 0x1400A64E0 | g_AesTe0_2/1_2/2_2/3_2 | DWORD[256]×4 | AES 加密 T-盒表 (第二组) |
| 0x1400A74E0 | g_AesTd0_2/1_2/2_2/3_2 | DWORD[256]×4 | AES 解密 T-盒表 (第二组) |
| 0x1400A84E0 | g_Filter | PFLT_FILTER | Minifilter 句柄 |
| 0x1400A84E8 | g_Pointer | volatile ULONG64 | 链表头指针 (保护链) |
| 0x1400A84F0 | g_GlobalTable | volatile ULONG64[16384] | 全局表 (核心数据存储) |
| 0x1400A84F8 | g_DriverObjectPtr | ULONG64 | 驱动对象指针 (GT 索引 1) |
| 0x1400A87F8 | g_CurrentProcess | ULONG64 | 当前进程 EPROCESS |
| 0x1400AC8A8 | g_EncryptionKey | ULONG64 | 通信加密密钥 |
| 0x1400AC8B0 | g_CurrentProcessId | ULONG64 | 当前进程 PID |
| 0x1400CCFC0 | g_Event | KEVENT | 全局事件 (同步锁) |
| 0x1400CCFE0 | g_SymlinkNameBuffer | WCHAR[256] | 符号链接名称缓冲区 |
| 0x1400CD1E0 | g_DeviceNameBuffer | WCHAR[256] | 设备名称缓冲区 |
| 0x1400CD3E0 | g_Mutex | KMUTEX | 全局互斥体 |
| 0x1400CD418 | g_CommPortContext | ULONG64 | 通信端口回调上下文 |

### 9.2 .rdata 段常量数据

| 地址 | 名称 | 类型 | 说明 |
|------|------|------|------|
| 0x14008CA40 | g_ShellCodeBuffer | BYTE[8] | ShellCode 缓冲区 (mov eax, 0x22; ret; int3) |
| 0x14008CA44 | g_ShellCodeMovEax | WORD | ShellCode 中的 mov eax 指令 |
| 0x14008CA50 | g_HalDispatchTable | ULONG64 | HalDispatchTable 地址 |
| 0x14008CA58 | g_HalDispatchTableEnd | ULONG64 | HalDispatchTable 结束地址 |
| 0x14008D600 | Registration | FLT_REGISTRATION | Minifilter 注册结构 (104 字节) |

### 9.3 AES 加密表布局

AES 加密密钥扩展使用运行时生成的查找表，位于地址 0x1400A40A0-0x1400A8200:

- **g_AesLogTable[256]** — GF(2^8) 对数表，用于有限域乘法
- **g_AesExpTable[256]** — GF(2^8) 指数表 (g_AesExpTable[0] = 0x01, g_AesExpTable[1] = 0x02, ...)
- **g_AesSbox[512]** — 前 256 字节为 S-Box，后 256 字节为逆 S-Box
- **g_AesRcon[10]** — 10 个轮常数 (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
- **g_AesTe0~Te3** — 加密 T-盒 (4×256 DWORDs，用于快速 AES 加密)
- **g_AesTd0~Td3** — 解密 T-盒 (4×256 DWORDs，用于快速 AES 解密)

## 10. 逆向分析进度

| 阶段 | 状态 | 说明 |
|------|------|------|
| 函数命名 | 完成 | 所有 1516 个函数已命名，0 个 sub_* 残留 |
| 函数目的注释 | 完成 | 所有核心函数（地址范围 0x140003B3C ~ 0x14008C7C4）已添加中文目的注释 |
| 参数重命名 | 部分完成 | 部分函数参数已重命名，MSVC 优化导致部分变量不可见 |
| 局部变量重命名 | 部分完成 | 约 50 个函数的局部变量成功重命名（ValidateProcessObject: 30, WalkObjectTypeList: 24 等） |
| 结构体创建 | 基础完成 | IRP_INPUT_HEADER, MD5_CONTEXT, GLOBAL_TABLE 索引定义, FLT_REGISTRATION |
| 全局表索引 | 完成 | 定义了 0~0x4000 范围内的关键索引 |
| 全局变量标注 | 完成 | 40+ 个全局变量已命名，含 AES 表、驱动状态、同步对象等 |
| 结构体分析 | 完成 | FLT_REGISTRATION (0x14008D600), UTF-8 解码表 (0x140094000) |
| 指令解码器分析 | 完成 | 60+ 个指令解码函数已分析（DecodeOpcode* 系列），覆盖 x86/x64 指令解码 |
| 文档输出 | 完成 | 本文档为最终版本 |

---

## 11. 源码组织（重构后）

逆向复刻完成后，源码已按子系统重组为四层目录结构（仅移动函数，未修改任何逻辑，`.sys` 保持 470,016 字节不变）。各子系统对应的源码文件映射如下：

### 11.1 framework/ — 基础框架（内存/缓冲区/工具/PE/加解密）

| 源文件 | 对应逆向子系统 |
|---|---|
| MemoryOps.c | 内存读写、GtRead/GtWrite 封装 |
| MemoryCleanup.c | 内存清理与缓冲释放 |
| Utility.c | 字节交换、字符串、通用工具函数 |
| Utf8Decoder.c | UTF-8 解码表 |
| PEDecoder.c | PE 文件解析 |
| DecodeTables.c | 指令解码查找表 |
| Crypto.c | AES/MD5/SHA1 加解密 |

### 11.2 kernel/ — 内核对象操作

| 源文件 | 对应逆向子系统 |
|---|---|
| ProcessMgmt.c | 进程管理（第 3.10 节对象枚举） |
| ThreadMgmt.c | 线程管理 |
| ObjectMgmt.c | 对象管理、对象类型枚举 |
| HandleMgmt.c | 句柄管理 |
| ModuleMgmt.c | 模块管理（第 3.14 节） |
| Registry.c | 注册表保护（第 3.12 节） |
| Minifilter.c | 文件系统 Minifilter（第 3.6 节） |
| ContextMgmt.c | 上下文管理与保护 |

### 11.3 services/ — 服务层（IOCTL 分发/SSDT/协议）

| 源文件 | 对应逆向子系统 |
|---|---|
| IoctlDispatch.c | IOCTL 分发 + InitCommandHandlerTable + 命令分发表（第 3.3/3.13 节） |
| Operation.c | Cmd* 命令处理函数（220+ 个） |
| SSDT.c | SSDT Hook 引擎核心（第 3.5 节） |
| SsdtHook.c | SSDT Hook 表构建/安装/卸除 |
| SyscallTable.c | syscall 表枚举/复制 |
| Protocol.c | 通信协议（第 5 节） |
| QueryDriver.c | 驱动查询 |
| TailHelpers.c | 尾部辅助函数 |

### 11.4 features/ — 功能层（系统信息/PE 解析/服务表/磁盘/模块枚举/回调）

| 源文件 | 对应逆向子系统 |
|---|---|
| SystemInfo.c | 系统信息查询 |
| PeParse.c | PE 节区解析 |
| ServiceTable.c | 服务表解析 |
| DiskQuery.c | 磁盘扇区查询 |
| ModuleEnum.c | 模块链表演示枚举 |
| Callback.c | 回调例程（通知/电源/关机） |

### 11.5 头文件

| 头文件 | 内容 |
|---|---|
| XPCHunterDrv.h | 伞形头：include 子头 + 全部函数声明（~826 条） |
| xpc_basic.h | 基础类型/宏/字节交换 |
| xpc_gt_enum.h | GLOBAL_TABLE_INDEX 枚举 + GT 别名 |
| xpc_ioctl.h | 设备名/IRP 常量/IOCTL 码/CMD opcode |
| xpc_structs.h | 结构体定义（IRP_INPUT_HEADER、MD5_CONTEXT、PCOMMAND_HANDLER） |
| IDA 数据库保存 | 已保存 | 多次保存，包含所有命名和注释 |