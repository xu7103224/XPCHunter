# XPCHunter 项目规则

## 项目目标
1:1 完整复刻 PCHunter 的 View++_Driver64.sys 驱动（作者 Linxer），所有 1516 个函数和所有数据结构都必须完整复刻，不得有任何缩水或简化。

---

## 一、核心原则（必须严格遵守）

### 1. 必须先逆向，再开发
- **严禁在逆向完成之前编写任何实现代码**
- 严禁写占位方法/空函数/骨架代码（如 `return 1;` 带注释说"TODO"）
- 每个函数必须先在 IDA Pro 中完成逆向分析（命名、参数、逻辑），然后才能编写实现
- 遵守顺序：IDA 逆向分析 → 输出分析文档 → 编写实现代码

### 2. 1:1 完整复刻，不得缩水
- 原 .sys 的所有 1516 个函数必须完整复刻，不能有任何简化或省略
- 所有数据结构必须重建，不能省略任何字段
- 所有功能必须实现，不能裁剪

### 3. 非代码文字内容全部使用中文
- 文档、注释、分析报告、说明等均使用中文
- 代码中的变量名、函数名使用英文

### 4. 使用 VS2019 + WDK 开发驱动
- 项目必须可在 VS2019 中编译
- Windows 10 SDK 10.0.19041.0
- WDK 10.0.19041.0

---

## 二、逆向分析规则

### 2.1 函数命名规则
- 每个函数必须根据功能进行合理命名，杜绝 `sub_XXX` 命名
- 函数名使用英文 PascalCase，如 `ParseNtHeaders`、`LookupExportFuncAddr`
- 函数名应准确反映函数功能，若不确定则根据上下文推断并标注注释

### 2.2 变量命名规则
- 所有局部变量（v1, v2, v3...）必须重命名为有意义的名称
- 变量名使用英文 PascalCase，如 `ExportDirVa`、`SectionCount`、`KernelBase`
- 临时循环变量：`Index`、`SectionIndex`、`EntryCount` 等
- 状态变量：`Result`、`Status`、`IsMatch`、`ProcessAttached` 等
- 指针变量：`BufferPtr`、`DataBuffer`、`InputBuffer`、`OutputBuffer` 等
- 大小变量：`BufferSize`、`ImageSize`、`NameLength` 等
- 地址变量：`TargetAddress`、`ImageBase`、`ExportDirVa` 等

### 2.3 函数参数命名规则
- 所有函数参数（a1, a2, a3...）也必须重命名为有意义的名称
- 参数名使用英文 PascalCase
- 常见参数模式：
  - `Address` 或 `TargetAddress` — 地址参数
  - `Flags` — 标志位参数
  - `Buffer`、`BufferSize` — 缓冲区参数
  - `ProcessId`、`ThreadId`、`ParentId` — ID 参数
  - `Context` 或 `CallbackContext` — 回调上下文参数
  - `Argument1`、`Argument2` — 通用回调参数（当无法确定时）
  - `pContext`、`pResult` — 输出参数（加 p 前缀表示指针输出参数）

### 2.4 结构体命名规则
- 所有结构体（`__int64` 数组、`_DWORD` 等）必须创建 IDA 结构体类型
- 结构体名使用大写前缀 + PascalCase，如 `_IRP_INPUT_HEADER`、`_MD5_CONTEXT`
- 所有字段必须标注，不能省略
- 全局表（~16000 条目）中的每个索引偏移必须枚举定义

### 2.5 工作顺序
- 按地址从低到高顺序处理（IDA 中按地址排序）
- 对每个函数依次执行：反编译 → 理解逻辑 → 重命名参数 → 重命名局部变量 → 标注注释
- 纯标准算法函数（AES、MD5、SHA1 等标准实现）可以跳过局部变量重命名，但必须标注函数名和注释

### 2.6 特殊情况处理
- **反编译失败**：切换到汇编视图分析，通过汇编指令理解函数逻辑
- **编译器优化变量合并**：若变量名在 IDA 中找不到（已优化掉），跳过不报错
- **内联函数**：IDA 可能将小函数内联，此时跳过源函数，直接处理调用方
- **thunk 函数**：直接跳转到目标函数，无需重命名

---

## 三、IDA Pro 操作规范

### 3.1 工具链
- 使用 IDA Pro MCP 工具进行逆向分析（通过 ida-pro-mcp MCP 服务器）
- IDA 数据库文件：`View++_Driver64.sys.i64`
- 使用 `decompile` 获取伪代码，`rename` 进行重命名，`set_type` 修改类型

### 3.2 操作流程
1. `decompile(addr)` — 获取函数的伪代码
2. 分析函数逻辑，理解参数含义
3. 使用 `rename` 的 `func` 字段重命名函数参数（如 a1 → Address）
4. 使用 `rename` 的 `local` 字段重命名局部变量（如 v1 → ExportDirVa）
5. 必要时使用 `set_comments` 添加注释
6. 移动到下一个函数继续

### 3.3 rename 工具参数格式
```
func: [{addr: "0x...", name: "NewName"}]    // 重命名函数
local: [{func_addr: "0x...", old: "v1", new: "NewName"}]  // 重命名局部变量
// 注意：重命名参数（a1, a2...）使用 local 字段，func_addr 指向当前函数
```

---

## 四、开发实现规则

### 4.1 代码规范
- 使用 C 语言编写（MSVC 编译器）
- 遵循 WDK 内核驱动编程规范
- 变量名、函数名使用英文，注释使用中文
- 结构体使用 `typedef struct _XXX { ... } XXX, *PXXX;` 格式

### 4.2 项目结构
```
XPCHunter/
├── samples/                    # 原始样本
│   └── PCHunter_2024.09.02/
│       └── View++_Driver64.sys
├── build/
│   └── build.bat               # 编译脚本（两步法：msbuild 编译 + link 链接）
│                               # 产物输出到 build/bin、build/obj
├── tools/                      # 辅助脚本（历史构建/重命名工具）
├── XPCHunterDrv/               # 仅源码（不含 build/日志）
│   ├── XPCHunterDrv.vcxproj    # VS2019 项目文件 (PlatformToolset=v142)
│   ├── XPCHunterDrv.sln
│   ├── inc/                    # 头文件
│   │   ├── XPCHunterDrv.h      # 伞形头：include 子头 + 全部函数声明
│   │   ├── xpc_basic.h         # 基础类型/宏
│   │   ├── xpc_gt_enum.h       # GLOBAL_TABLE_INDEX 枚举 + GT 别名
│   │   ├── xpc_ioctl.h         # 设备名/IRP 常量/IOCTL 码/CMD opcode
│   │   └── xpc_structs.h       # 结构体定义
│   └── src/                    # 四层组织
│       ├── DriverEntry.c       # 驱动入口
│       ├── GlobalTable.c       # 全局表
│       ├── framework/          # 基础框架：内存/缓冲区/工具/PE/加解密
│       │   └── MemoryOps.c, MemoryCleanup.c, Utility.c, Utf8Decoder.c,
│       │       PEDecoder.c, DecodeTables.c, Crypto.c
│       ├── kernel/             # 内核对象操作
│       │   └── ProcessMgmt.c, ThreadMgmt.c, ObjectMgmt.c, HandleMgmt.c,
│       │       ModuleMgmt.c, Registry.c, Minifilter.c, ContextMgmt.c
│       ├── services/           # 服务层：IOCTL 分发/SSDT/协议
│       │   └── IoctlDispatch.c, Operation.c, SSDT.c, SsdtHook.c,
│       │       SyscallTable.c, Protocol.c, QueryDriver.c, TailHelpers.c
│       └── features/           # 功能层：系统信息/PE 解析/服务表/磁盘/模块枚举/回调
│           └── SystemInfo.c, PeParse.c, ServiceTable.c, DiskQuery.c,
│               ModuleEnum.c, Callback.c
├── docs/
│   ├── reversing/
│   │   └── View++_Driver64_逆向分析报告.md
│   └── build/
│       └── 编译说明.md          # 编译环境与步骤
└── CLAUDE.md
```

### 4.4 编译方法（两步法）

由于 VS2019 BuildTools 不含 `WindowsKernelModeDriver10.0` 工具集（标准 WDK 驱动项目用此工具集），当前项目使用 `PlatformToolset=v142` + 手动链接。

**编译环境：**
- VS2019 BuildTools（MSVC v142）
- WDK 10.0.19041.0（仅 headers/libs）
- 调用 `vcvarsall.bat x64` 设置环境变量后，使用 msbuild 编译 + link 链接

**两步编译流程：**

```bat
REM 第一步：设置环境
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64

REM 第二步：msbuild 编译（/t:ClCompile 仅编译）
REM 在仓库根执行，项目文件位于 XPCHunterDrv\ 子目录
msbuild XPCHunterDrv\XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:ClCompile

REM 第三步：手动链接（msbuild 在 v142 下不自动链接驱动）
REM 产物输出到仓库根 build\bin、build\obj（vcxproj 的 OutDir/IntDir 为 $(SolutionDir)..\build\...）
link /nologo /kernel /subsystem:native /entry:GsDriverEntry /base:0x140000000 /fixed:no /driver /merge:.data=.text /manifest:no ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.19041.0\km\x64" ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.19041.0\km\x64\crt" ^
    /out:"build\bin\Release\x64\XPCHunterDrv.sys" ^
    /pdb:"build\bin\Release\x64\XPCHunterDrv.pdb" ^
    /map:"build\bin\Release\x64\XPCHunterDrv.map" ^
    "build\obj\Release\x64\*.obj" ^
    ntoskrnl.lib hal.lib fltMgr.lib wmilib.lib ^
    BufferOverflowK.lib bufferoverflowfastfailk.lib
```

**快速编译（使用 build.bat，在仓库根执行）：**
```bat
cd E:\Work\Dev\Windows\wmprotected\APK\XPCHunter
build\build.bat              # Release x64
build\build.bat Debug x64    # Debug x64
build\build.bat Clean        # 清理
```

**注意：** 不能直接调用 `msbuild XPCHunterDrv\XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64` 完成全部编译，因为 `v142` 工具集在未安装完整 WDK 的情况下无法自动完成驱动链接步骤。必须两步走：msbuild 编译 → 手动 link 链接。

### 4.5 新增源文件维护规则
- 新增 `.c` 文件后，必须同步在 `XPCHunterDrv.vcxproj` 的 `<ClCompile>` 列表中添加对应条目
- 新增跨文件调用的函数，必须在 `inc/XPCHunterDrv.h`（伞形头）中添加 `extern` 声明
- 函数声明与定义签名必须逐字一致，避免 C4028 形参不匹配警告
- 删除源文件后，需执行 `build\build.bat Clean` 清理残留 `.obj`，防止 LNK2005 重复符号
- MissingFuncs.c 存放暂未从 IDA 逆向实现的函数存根
- 所有函数签名必须与 XPCHunterDrv.h 中的声明完全一致
- 已实现真实逻辑的函数保持在文件头部
- 新增函数时同时在头文件添加 `extern` 声明
- 函数既已在其他 .c 文件中实现的，不得在 MissingFuncs.c 中重复定义

### 4.6 禁止批量处理
- **严禁使用脚本批量处理反编译或代码生成**
- 严禁使用正则表达式或 Python 脚本批量修改 header 声明
- 严禁使用并行 Agent 批量处理多个函数的反编译实现
- 每个函数必须单独处理：IDA 反编译 → 理解逻辑 → 手动编写实现 → 手动更新 header 声明
- 每次只处理一个函数，完成后构建验证，再处理下一个
- 违反此规则会导致 header 损坏、签名不匹配等难以修复的问题

### 4.3 源文件与头文件对应
- `inc/XPCHunterDrv.h` — 所有函数声明、类型定义、常量定义
- 每个 `.c` 文件实现对应子系统的功能
- 全局表索引在 `XPCHunterDrv.h` 中通过 `#define` 定义

---

## 五、文档输出规范

### 5.1 必须输出的文档
1. **逆向分析文档** — 记录所有函数分析和数据结构重建结果
2. **开发文档** — 记录实现的架构设计和模块说明
3. **编译说明** — 记录编译环境配置和步骤

### 5.2 文档格式
- 使用 Markdown 格式
- 所有非代码内容使用中文
- 函数名、变量名、代码片段使用英文原文

---

## 六、禁止行为
- ❌ 写占位函数 / 空函数 / 骨架代码
- ❌ 在逆向完成前编写实现代码
- ❌ 简化或省略原驱动中的任何功能
- ❌ 使用 TODO 注释替代实际实现
- ❌ 裁剪数据结构或省略字段
- ❌ 跳过函数参数重命名（a1, a2 必须重命名）
- ❌ 跳过局部变量重命名（v1, v2 必须重命名，纯标准算法除外）

---

## 七、完整工作流程

### 7.1 总体流程
1. IDA Pro 逆向分析：对每个函数命名、分析参数、理解逻辑
2. 重命名函数参数和局部变量
3. 创建 IDA 结构体类型：重建所有数据结构
4. 记录分析文档到 docs/reversing/
5. 确认所有 1516 个函数均已逆向分析完成
6. 编写完整的实现代码
7. 编译测试

### 7.2 单函数处理流程

**第一步：IDA 逆向分析（必须完成，不可跳过）**
1. 调用 `decompile(addr)` 获取伪代码
2. 分析函数整体逻辑和功能
3. 确定函数名，使用 `rename(func)` 重命名函数
4. 分析每个参数（a1, a2...）的含义，使用 `rename(local)` 重命名
5. 分析每个局部变量（v1, v2...）的含义，使用 `rename(local)` 重命名
6. 对关键逻辑添加注释
7. 移动到下一个地址继续

**第二步：反编译结果整理到项目（参考 EnumProcessAndInitObjects 模式）**
- 必须先完成 IDA 中的变量/参数重命名，再更新 C 代码
- 使用 `decompile` 获取最终伪代码，**不得直接复制粘贴**原始伪代码中的 `a1`、`v1` 等占位名到 C 代码
- 变量重命名规则：
  - 读取的全局表偏移 → 保留原名 `GtXxx`（如 `GtEprocessField30`）
  - 从 GtRead 读取的值 → 根据功能命名（如 `ObjectTableOffset`、`ObjectTablePtr`）
  - 分配/释放的缓冲区 → 根据用途命名（如 `Buffer`、`BufferPtr`）
  - 循环计数器 → 根据遍历对象命名（如 `EntryCount`、`LoopCount`）
  - 数组索引指针 → 根据条目类型命名（如 `CurrentEntry`）
  - 函数参数 → 根据语义命名（如 `Process`、`Flags`）
- 代码结构整理：
  - 合并相关变量声明，去掉冗余的初始化为 0 的声明
  - 保留原始伪代码中的所有逻辑分支和判断条件，不得简化
  - 每个变量只声明一次，不得重复声明
  - 变量声明按照使用顺序排列
- 注释：函数注释写明功能描述，变量注释在变量名中体现（不额外加行注释）
- 完成后调用 `build/build.bat` 验证编译通过

### 7.3 全局数据结构处理
- 全局表（qword_1400A84F0）中的常量偏移定义为 `#define GT_XXX` 宏
- 通信协议、IOCTL 码、设备路径等常量均在头文件中定义
- 函数指针表（命令处理函数表）起始于全局表索引 2337