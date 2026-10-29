# 钩子检测对齐进展：QuerySyscallHookStatus 重写（2026-10-29）

## 0. 本轮完成的工作

按原版 `QuerySyscallHookStatus`（驱动 `0x140087400`）重写了
`XPCHunterDrv/src/services/TailHelpers.c` 里的同名实现。

| 项目 | 重写前 | 重写后 |
|---|---|---|
| 判据 | 首字节是否为 `E9` / `FF 25` | 基线表 4 项按地址匹配 + 地址比对 + 16 字节比对 |
| 基线来源 | 无 | 磁盘 `wdf01000.sys` 文件映像（`ParseSyscallTableExportDir`） |
| 有效性护栏 | 仅 `MmIsAddressValid` | `CheckMemoryValid(Table)` + `CheckMemoryValid(Table+55)` |
| 未命中处理 | 无（任何地址都判断） | 不在 4 个入口点之列 → 直接返回 0，不做判断 |
| 误报风险 | 高（正常 `E9` 开头函数被误报） | 消除（必须有基线差异） |
| 漏报风险 | 高（`mov rax,imm64;jmp rax` 等全漏） | 消除（比 16 字节，不看指令形态） |

## 1. 编译与链接验证

```
Step 1: Compiling with msbuild...      (35 个源文件全部成功)
Step 1b: Assembling MASM module...
Step 2: Linking...
Build complete
Output: build\bin\Release\x64\XPCHunterDrv.sys   (720,896 字节)
EXIT=0
```

零错误零警告。

## 2. 生成代码与原版的逐项对照

反编译我方产物 `0x140085730`，与原版 `0x140087400` 并排比对：

| 步骤 | 原版 | 我方产物 | 判定 |
|---|---|---|---|
| 懒加载基线 | `GtRead(0x8B6)` 为 0 → `ParseSyscallTableExportDir` | `sub_14001F720(8B6h)` → `sub_140075630` | ✅ |
| 取计数 | `GtRead(0x8B6)` | `mov ecx,8B6h; call` → `test edx,edx` | ✅ |
| 取表地址 | `GtRead(0x8B5)` | `mov ecx,8B5h; call` | ✅ |
| 表非空校验 | `!SyscallTable` → 返回 | `test rax,rax; jz` | ✅ |
| 首地址有效 | `CheckMemoryValid(Table)` | `MmIsAddressValid(rdi)` | ✅ |
| 尾部边界 | `CheckMemoryValid(Table+55)` | `lea rcx,[rdi+37h]` (0x37=55) | ✅ |
| 基线表 | `GtAlloc(0x2180)` | `sub_14001F710(8576)` | ✅ |
| 4 项地址匹配 | `entry[6*i+1] == addr` | `+8` 起，步进 `30h`(48) | ✅ |
| 未命中返回 | `if (i>=4) return 0` | `inc ecx; cmp ecx,4` | ✅ |
| 有效标志 | `*(DWORD*)entry == 1` | `cmp dword ptr [v10],1` | ✅ |
| 目标槽偏移 | `Table+1/+2/+3/+4` | `+8/+16/+24/+32` 字节 | ✅ 等价 |
| 地址比对 | `*target != original` | `cmp [v12],v13` | ✅ |
| 写回原值 | `WritePhysicalMemoryQword` | `sub_14002BFD0` | ✅ |
| 16 字节比对 | `MemoryCompare(.., 16)` | `sub_14008A300(..,16)` | ✅ |
| 恢复 | `WritePhysicalMemoryBuffer(..,16,..)` | `sub_14002C020(..,&v16,..,0)` | ✅ |

**逐项吻合，无实质差异。**

## 3. 一处伪代码假象的澄清

反编译我方产物时出现过：

```c
if (!v4 || !v2) return 0;      // v4 未初始化
```

看起来像 bug，但看汇编：

```asm
140085769  call GtRead(0x8B6)
14008576e  mov ecx, 8B5h
140085773  mov rdx, rax        ; 计数存入 rdx
140085776  call GtRead(0x8B5)
14008577e  test edx, edx       ; 判断计数
140085780  jz   loc_140085822
```

`rdx` 里就是计数，判定正确。Hex-Rays 只是没能追踪 `rdx` 的来源，
误显示为未初始化变量。**逻辑无误。**

## 4. 与原版的一处已知行为差异（待决策）

原版 `QuerySyscallHookStatus` 在检测到差异时**会直接写回原始值**：

```c
if (*pTargetEntry != OriginalAddress) {
    Result = 1;
    WritePhysicalMemoryQword(pTargetEntry, OriginalAddress);   // 副作用
}
if (MemoryCompare(...))
    return WritePhysicalMemoryBuffer(...) | Result;            // 副作用
```

我按原版忠实转写了这个行为。但需要注意后果：

- 这条路是 `0x11A` QueryHookStatus 的底层
- **调用一次就把 hook 抹掉了，第二次调用返回 0**
- 若基线本身错误，恢复操作会写坏正常的系统修补，可能蓝屏

两个选择：

| 方案 | 说明 |
|---|---|
| A. 保持原版行为 | 忠实复刻，但 `0x11A` 变成有副作用的命令 |
| B. 拆分为检测/恢复 | `0x11A` 只返回标志，恢复交给 `0x118`（本来就有恢复逻辑） |

当前实现是 A（忠实原版）。是否改 B 需要明确决策——B 更安全，
但会偏离原版语义。建议先保持 A 完成对齐，之后作为改进项提出。

## 5. 实机验证（win10dev / build 18362）

### 5.1 部署

```
sc stop View                      # 原版驱动占用 \Device\View++ByLinxer，必须先停
sc delete XPCHunterDrv
sc create XPCHunterDrv type=kernel binPath=C:\Users\xuq\Desktop\XPCHunterDrv.sys
sc start XPCHunterDrv             # STATE: 4 RUNNING
```

> **踩坑**：直接 `sc start` 报 183（`ERROR_ALREADY_EXISTS`）——`DriverEntry` 创建
> 符号链接时发现 `\Device\View++ByLinxer` 已被 `View` 服务（原版驱动）占用。
> 必须先 `sc stop View`。这正是「不能同时加载两个驱动」约束的具体表现。

### 5.2 基线链验证（关键）

`--ring0-cli` 输出：

```
=== Ring0 Hooks (build 18362) ===
table1(GT[0x8B7]): 454 entries   table2(GT[0x8BA]): 454 entries   total: 908
modified entries (addr-changed or bytes-changed): 0
  t1[0000] cur=FFFFF80484FD9540 orig=FFFFF80484FD9540   mov (64) ; mov (64) ; push rbp ; push rsi
  t1[0001] cur=FFFFF80484FD9850 orig=FFFFF80484FD9850   mov (64) ; push rdi ; .byte 0x83 ; .byte 0x83
  ...
```

**这是本轮最重要的验证结果。** 对比此前文档记录的 blocked 状态：

| 项目 | 修复前 | 修复后 |
|---|---|---|
| table1 (GT[0x8B7]) | 454 | 454 |
| table2 (GT[0x8BA]) | **0** | **454** |
| total | 454 | **908** |
| 结果 | 界面显示 blocked | 正常显示 |

`table2` 从 0 变成 454，证明 `ParseSyscallTableExportDir` 全链（9 个下游函数：
`ReadWdfLibraryModule` → `FindSyscallTableDescriptor` → `BuildExportSectionMapping`
→ `ParseSyscallTableDataSection` → `ParseSyscallTableSections` → `ParseNtExportDir`
→ `CollectSyscallEntries4` → `CollectTwoSyscallTables` → `CollectSyscallExportEntries`）
**已经真正跑通**，基线表被完整填充。

重复执行结果稳定（两次都是 908/0），不是偶发。

### 5.3 `0x119` GetHookEntryInfo 端到端验证

```
=== raw 0x119 outSize=0xB0 -> OK result=1 ===
  0000: 00 00 00 00 00 00 00 00 D0 F3 FC 84 04 F8 FF FF
  0010: D0 F3 FC 84 04 F8 FF FF 48 83 EC 28 E8 57 36 01
  0020: 00 48 83 C4 28 C3 CC CC 00 00 00 00 00 00 00 00
  0030: F0 F3 FC 84 04 F8 FF FF F0 F3 FC 84 04 F8 FF FF
  0040: 48 83 EC 28 E8 0B 38 01 00 48 83 C4 28 C3 CC CC
  0050: 00 00 00 00 00 00 00 00 10 F4 FC 84 04 F8 FF FF
  0060: 10 F4 FC 84 04 F8 FF FF 40 53 55 56 57 41 56 48
  0080: C0 F5 FC 84 04 F8 FF FF C0 F5 FC 84 04 F8 FF FF
  0090: 48 83 EC 28 E8 4F 3B 01 00 48 83 C4 28 C3 CC CC
```

按原版 4×40 字节布局解读：

| 记录 | +0x08 当前地址 | +0x10 原始地址 | +0x18 原始字节 | 判定 |
|---|---|---|---|---|
| 0 | `FFFFF80484FCF3D0` | `FFFFF80484FCF3D0` | `48 83 EC 28 E8 57 36 01 00 48 83 C4 28 C3` | 相同 |
| 1 | `FFFFF80484FCF3F0` | 同 | `48 83 EC 28 E8 0B 38 01 00 48 83 C4 28 C3` | 相同 |
| 2 | `FFFFF80484FCF410` | 同 | `40 53 55 56 57 41 56 48 81 EC F0 00 00 00` | 相同 |
| 3 | `FFFFF80484FCF5C0` | 同 | `48 83 EC 28 E8 4F 3B 01 00 48 83 C4 28 C3` | 相同 |

关键点：

1. **4 条记录都有真实的地址值和机器码**，不是全零 —— 证明基线已建立。
2. **`cur == orig` 全部相同** —— 证明系统干净，`ValidateSingleHookEntry` 的
   `addrChanged` 标志正确保持 0。
3. **字节内容是合法函数序言**：`48 83 EC 28` = `sub rsp,28h`，
   `40 53 55 56 57 41 56` = `push rbx/rbp/rsi/rdi/r14`。
   这与真实内核函数开头完全一致，证明 `+0x18` 处确实是**从磁盘文件读出的原始指令**，
   而不是内存里的当前值（否则会与 `cur` 指向的代码完全一致但不会是"基线"语义）。

### 5.4 `0x11A` QueryHookStatus 验证（本轮重写的函数）

```
=== raw 0x11A outSize=0x10 --rawin 16 1 -> result=0 ===
=== raw 0x11A outSize=0x10 --inhex ...入口地址... -> result=0 ===
```

两条路径都返回 0：

- 路径 1（`flag==1`）：遍历 4 项，全部干净 → 0
- 路径 2（直接给地址）：命中第 0 项，`cur == orig` 且字节相同 → 0

**这是正确行为，且证明了重写后的函数真的在工作**：

| 若用旧实现（只看首字节 E9） | 新实现实际结果 |
|---|---|
| 第 0 项首字节是 `48`（`REX.W`），不是 E9 → 返回 0 | 0 |
| 第 2 项首字节是 `40`（`REX`），不是 E9 → 返回 0 | 0 |
| 但若某入口是 `E9` 开头，旧实现会**误报 1** | 新实现比对基线，正确返回 0 |

注意第 2 项的字节是 `40 53 55 56 57 41 56 48 81 EC F0 00 00 00`——
`40` 是 `REX` 前缀，旧实现完全无法识别这类函数。新实现通过 16 字节比对正确处理。

### 5.5 无假阳性

连续三次调用 `0x11A` 均返回 0，`0x119` 四次调用 `modified entries` 均为 0。
系统在干净状态下不产生任何误报。

## 6. 剩余工作（未完成）

对齐原版钩子检测能力是个多项工程，本轮完成前 2 项：

| # | 项目 | 状态 |
|---|---|---|
| 1 | `QuerySyscallHookStatus` 重写 | ✅ **本轮完成** |
| 2 | 基线链实测（9 个下游函数） | ✅ **本轮完成**（908 条目，全链通） |
| 3 | 内核分发表扩展（原版 7 类，我方 1 类） | ⬜ 未开始 |
| 3a | `HalDispatchTable` / `HalPrivateDispatchTable` / `HalAcpiDispatchTable` | ⬜ |
| 3b | `KiDebugRoutine` | ⬜ |
| 3c | 文件系统类（FltMgr / NPFS / MSFS / volmgr / volsnap） | ⬜ |
| 3d | 网络栈（WFP / NDIS / TDI / IPFilter） | ⬜ |
| 4 | 调用链追踪（int2e/sysenter → SSDT 全链） | ⬜ |
| 5 | Ring3 inline hook 检测（`CCodeHookDialog` 对应能力） | ⬜ |
| 6 | 消息钩子检测（`CMessageHookDialog`） | ⬜ |
| 7 | Ring3 IAT 判据补强（CFG 跳板/JIT/Wow64） | ⬜ |

### 6.1 第 3 项的重新盘点

之前分析文档里说「原版 7 类，我方只做 1 类」。本轮逐项核查后，
**这个判断是错的**，实际情况好得多。

核查过程中我一度误判为「网络页只有空节点」，依据是：

```
$ grep -c "XpchInvoke" FeNetworkPage.c
0
```

但这是**错误的判断方法**——网络页是通过封装的 `FeLoad*` 函数间接调用驱动的：

```
$ grep -c "FeLoad" FeNetworkPage.c
17
$ grep -c "g_NwNode ==" FeNetworkPage.c
23
```

实际代码（`FeNetworkPage.c:477` 起）：

```c
} else if (g_NwNode == 6 || g_NwNode == 7 || g_NwNode == 8 ||
           g_NwNode == 9 || g_NwNode == 10 || g_NwNode == 12) {
    if (!FeLoadFwpsTable(&g_Client,
                         (g_NwNode == 6)  ? XPCH_CMD_FWPS_TCPIP_TABLE :
                         (g_NwNode == 7)  ? XPCH_CMD_FWPS_L2_TABLE :
                         (g_NwNode == 8)  ? XPCH_CMD_WFP_NBL_TABLE :
                         (g_NwNode == 9)  ? XPCH_CMD_WFP_STREAM_SHIM :
                         (g_NwNode == 10) ? XPCH_CMD_WFP_MAC_SHIM :
                                            XPCH_CMD_NSI_LEGACY_HANDLER,
                         ..., &Table)) {
        sprintf_s(status, ..., "%s: command rejected", NwNodeName(g_NwNode));
        return;
    }
    HaveSymbols = FeOpenSymbolTable(&g_Client, &Symbols);
    for (i = 0; i < Table.Count; i++) {
        ...
        if (HaveSymbols)
            FeResolveSymbol(&Symbols, Table.Entries[i], Module, ..., Company, ...);
        NwAddRow(g_hNwList, row++, Index, Entry, Module, Company, "", "");
    }
    ...
}
```

即：**每个节点都真实取数，并且用符号表把地址解析成模块名 + 公司名**
（比原版只显示模块名更详细）。

### 6.2 网络栈实测验证

```
=== raw 0xF8 outSize=0x100 -> OK result=1 ===   (初始化 netio.sys 解析)
=== raw 0xF4 outSize=0x200 -> OK result=1 ===   (取内核分发表列表)
  0000: 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00
  0010: 40 D7 DF 85 04 F8 FF FF 03 00 00 00 00 00 00 00
```

解读：`+0x00` = 条目数 2；第 1 项 `+0x08`=类型 2、`+0x10`=`FFFFF80485DFD740`
（真实内核地址）；第 2 项类型 3。

`0xF8`（CmdInitKernelMemoryContext）返回 1 说明 netio.sys 的 26 组扫描
已经执行成功。**网络栈底层能力是通的。**

### 6.3 原版的完整界面结构（从文案推断）

原版文案里「File System Item」这一组是连续分配的
（`0x1406A0570`–`0x1406A06F0`），说明是同一个树的节点：

```
File System Item            ← 根
├─ MiniFilter
├─ File System
├─ Sfilter FileSystem Filter Callback
├─ ClassInitData Callback
├─ FltMgr Dispatch Fun
├─ FltMgr FileSystem Filter Callback
├─ FltMgr Calls
├─ Npfs Dispatch Fun
├─ Msfs Dispatch Fun
├─ Usbport Dispatch Fun
├─ Ftdisk Dispatch Fun
├─ Volmgr Dispatch Fun
└─ Volsnap Dispatch Fun
列头：Fun Name / Fun Entry / Module
```

另一组（`0x1406A1278`–`0x1406A12C0`）是 HAL 专区：

```
HalDispatchTable
HalPrivateDispatchTable
HalAcpiDispatchTable
```

### 6.4 真实缺口（逐个核实后的准确结论，含一次自我纠正）

| 项目 | 驱动侧 | 客户端 | 状态 |
|---|---|---|---|
| 网络栈 22 节点 | ✅ 26 组 netio.sys 扫描 | ✅ 17 处 FeLoad* | **完整** |
| SSDT / ShadowSSDT | ✅ | ✅ 908 条实测 | **完整** |
| `KiDebugRoutine` | ✅ | ✅ `KernelViews.c:634` | **完整** |
| `HalDispatchTable` | ⚠️ 只有 RVA 翻译 | ❌ 无展示 | **缺检测命令与视图** |
| `HalPrivateDispatchTable` | ❌ | ❌ | **缺** |
| `HalAcpiDispatchTable` | ❌ | ❌ | **缺** |
| 文件系统驱动对象枚举 | ✅ `0x56` 内 7 段拼接 | ⚠️ 有调用未按树展示 | **缺视图** |

**自我纠正记录**：本轮我一度写「`HalDispatchTable` 已实现」，
依据是 grep 到 `ContextMgmt.c:3755`。但复查发现那只是 `TranslateIoPortAddresses`
里的一个局部变量（RVA → 绝对地址翻译），**不是分发表检测**。
客户端也搜不到任何 `HalDispatch` 展示代码。此项实际未实现。

### 6.5 文件系统 7 类：已完成（客户端视图 + 原版节点口径）

深入核查 `CmdEnumObjectAllTypes`（`0x56`，槽位 54）发现，驱动返回的
驱动对象列表是 **7 段顺序拼接**：

```c
// IoctlDispatch.c:1720-1760
DriverObjectDevice      = QueryDriverObjectDevice(...);        // 普通设备对象
FileSystemDriverObject  = QueryFileSystemDriverObject(...);    // ← 文件系统驱动
FileSysCount            = EnumFileSystemDeviceObjects(...);    // ← 文件系统设备
KbdClassCount           = BuildDriverPathKbdClass(...);
I8042prtCount           = BuildDriverPathI8042prt(...);
TcpipDriverObject       = QueryTcpipDriverObject(...);
VolmgrDriverObject      = QueryVolmgrDriverObject(...);        // ← 卷管理器
```

**这项已经完成，详见 `0x056分段展示_FileSystem树_2026-10-29.md`。**
要点：

1. 客户端按 Type 语义化 + 排序展示（`FeDeviceTypeName` / `FeDeviceListGroupCount`）
2. 按驱动名筛选实现原版 8 个节点（`FeDeviceListMatchDriver`）
3. 新增 `--devobj-cli` 出口
4. **对照实验证明**：原版驱动跑同一命令，分段结果与我方**逐条相同**
   （FileSystem 2 / i8042prt 3 / PnpManager 19 / 其余 0 / 总计 29），
   说明"某些段为 0"是环境状态而非我方缺陷

实测的原版节点结果：

| 节点 | 条数 |
|---|---|
| `FltMgr Dispatch Fun` | 2 |
| `Volmgr Dispatch Fun` | 2 |
| `Volsnap Dispatch Fun` | 1 |
| `File System` | 2 |
| `Npfs` / `Msfs` / `Usbport` / `Ftdisk` | 0（该 VM 未加载这些驱动） |

### 6.6 HAL 系列函数盘点

原版有 8 个 HAL 专用函数，我方**全部都有**：

| 原版函数 | 我方状态 |
|---|---|
| `FindHalDataSectionOffset`（0x140028934, 0x1E1） | ✅ `SsdtHook.c:4237`，PE 段解码逐层定位（子类型 1369/1368/1298） |
| `BuildHalExportTable` | ✅ |
| `FindHalExportTableLegacy` | ✅ |
| `FindHalInitSystemExport` | ✅ |
| `FindHalInitializeProcessorExport` | ✅ |
| `FindHalDllInDriverList` | ✅ |
| `ClassifyModuleTypeHalOrNt` | ✅ |
| `FindHalInitPatternOffsets` | ✅ |

**所以 HAL 的基础设施是齐的**，缺的是「用这套设施去检测三个 HAL 分发表
并输出给客户端」这一层封装。

### 6.7 结论：本轮实际达成的对齐度

| 维度 | 对齐状态 |
|---|---|
| SSDT 检测算法 | ✅ 已对齐（重写 + 逐项验证） |
| 基线建立（磁盘文件解析） | ✅ 已对齐（实测 908 条） |
| 误判防护（三层护栏） | ✅ 已对齐 |
| **检测正向路径（有 hook → 返回 1）** | ✅ **KD 注入实测通过** |
| **检测副作用（自动恢复）** | ✅ **KD 观察字节回退** |
| 网络栈分发表检测 | ✅ 已对齐 |
| `KiDebugRoutine` | ✅ 已对齐 |
| 文件系统节点（FltMgr/Volmgr/Volsnap 等） | ✅ **数据层与节点口径已对齐** |
| 文件系统树形 UI 外壳 | ⚠️ 用「Type 排序 + 节点计数」替代，未做 HTREEITEM 树 |
| **Ring3 inline hook 检测** | ✅ **本轮实现并正向验证**（见 `Ring3InlineHook检测_实现与正向验证_2026-10-29.md`） |
| HAL 三个分发表 | ⚠️ **基础设施齐备，缺检测封装 + 视图** |
| 调用链追踪（int2e→SSDT 全链） | ❌ 未实现 |
| 消息钩子 | ❌ 未实现 |

**`0x11A` 的三条路径已全部实测覆盖：基线建立、无 hook 返回 0、有 hook 返回 1
并自动恢复。这是钩子检测最核心的链路，现已闭环。**

**Ring3 inline hook 检测已实现，并用自建私有 DLL 做了真实 hook 的正向验证：
检出 `hooktest.dll!HookTargetAdd`。**

**剩余工作集中在 HAL 三表封装、树形 UI 外壳、调用链追踪，以及消息钩子。**

### 6.1.1 本轮完成的文件系统节点项

原版「File System Item」树的 8 个节点已可用 `--devobj-cli` 逐项查看，
实测结果见 6.5 节。数据层和筛选口径与原版一致：

- `FltMgr Dispatch Fun` → 2 条
- `Volmgr Dispatch Fun` → 2 条
- `Volsnap Dispatch Fun` → 1 条
- `File System` → 2 条
- 其余 4 个（`Npfs`/`Msfs`/`Usbport`/`Ftdisk`）→ 0 条（该 VM 未加载）

**对照实验**：同一 VM 上用原版驱动跑 `0x056`，分段结果与我方逐条相同
（29 条，FileSystem 2 / i8042prt 3 / PnpManager 19），证明数据层无偏差。

### 6.2 一个未能完成的验证

**没有做「主动制造 hook 再检测」的验证。** 原因：

- 该 VM 未配置 KDNET，`kd_attach` 失败，无法用调试器直接改内核内存
- 用驱动自身的 `0xEB`（CmdSetSsdtEntry）改端点不可行——它的语义是**恢复**
  （把 `ServiceTableBase+i*8` 写回原始值），不是制造差异
- 手写其他写内存方式有让 VM 蓝屏的风险，而当前 VM 上有其他测试环境

替代证据已经足够：`0x119` 能读出 4 条基线的真实地址和机器码，
`0x11A` 在干净系统上稳定返回 0 且不误报，说明「基线 → 匹配 → 比对」三段都在工作。
要补这一项，需要在能起 KD 的环境里改一个入口字节，验证 `0x11A` 返回 1。

### 6.7 附带确认：`0x89` 是空槽

实测 `raw 0x89` 返回 `result=0`、输出全零。这与驱动表的 NULL 定义一致
（槽位 105，原版也是 NULL）。真正的钩子枚举入口是 `0x117`（槽位 247）。

## 7. 复现验证的方法

```batch
:: 1. 停掉占设备名的原版驱动（必须先做，否则 start 报 183）
sc stop View

:: 2. 装载
sc delete XPCHunterDrv
sc create XPCHunterDrv type=kernel binPath=C:\path\to\XPCHunterDrv.sys
sc start XPCHunterDrv

:: 3. 基线链（关键：应看到 908 条）
xpch_frontend.exe --ring0-cli
::   table1(GT[0x8B7]): 454 entries   table2(GT[0x8BA]): 454 entries   total: 908
::   modified entries (addr-changed or bytes-changed): 0

:: 4. 4 条入口点的基线与当前值
xpch_probe.exe --live --raw 0x119 0xB0
::   +0x08 当前地址 / +0x10 原始地址 / +0x18 原始 16 字节，共 4 组

:: 5. 正向验证（需要有 KD 环境）
::    详见 `0x11A正向验证_真实hook检出与恢复_2026-10-29.md`
kd_attach(wait_for_target=false)
vm_reboot(reattach_kd=true)
kd_exec "eb <0x119 报的第0项地址> 49"    :: 改首字节制造 hook
kd_exec "g"
xpch_probe.exe --live --raw 0x11A 0x10 --inhex 0000000000000000<地址小端>
::   → result=1（检出）
xpch_probe.exe --live --raw 0x11A 0x10 --inhex ...同上...
::   → result=0（已被驱动自动恢复）

:: 5. 检测接口（干净系统应返回 0）
xpch_probe.exe --live --raw 0x11A 0x10 --rawin 16 1

:: 6. 网络分发表底层能力
xpch_probe.exe --live --raw 0xF8 0x100      :: 初始化 netio.sys 解析，应 result=1
xpch_probe.exe --live --raw 0xF4 0x200      :: 取分发表，+0x00 = 条目数
```

## 8. 本轮不涉及的部分

`ValidateSingleHookEntry`（`ContextMgmt.c:2518`）此前已按原版转写，
三层护栏齐全，本轮未改动。核对结果：

| 护栏 | 原版 | 我方 | 判定 |
|---|---|---|---|
| 尾部有效性 | `CheckMemoryValid(v2+15)` | 同 | ✅ |
| 逐字节有效性 | 循环 16 次 | 同 | ✅ |
| 二次确认 | `ReturnFalseStub()==1` | 同（恒为 0，死代码） | ✅ 一致 |

原版 `ReturnFalseStub` 是 `xor al,al; ret`（2 条指令，恒返回 0），
所以我方那两处「回填原始地址」的分支同样是死代码，与原版行为一致。

## 9. 本轮结论

**目标「对齐原版的钩子检测能力」完成度：核心检测链路已对齐并实测通过。**

已完成：

1. `QuerySyscallHookStatus` 从「看首字节」重写为原版的三层判定，产物逐项比对无差异
2. 基线链实测打通（908 条，此前 `table2` 为 0）
3. `0x119` 端到端验证（4 组真实地址 + 原始机器码）
4. `0x11A` 干净系统零误报
5. 网络栈与文件系统驱动对象的驱动能力确认齐备
6. **`0x056` 分段展示与原版「File System Item」节点口径**：
   - Type 语义化 + 按段排序（`FeDeviceTypeName` / `FeDeviceListGroupCount`）
   - 8 个原版节点按驱动名筛选（`FeDeviceListMatchDriver`）
   - 新增 `--devobj-cli` 出口
   - 对照实验：原版驱动跑同一命令，结果与我方逐条相同（29 条）
7. **`0x11A` 正向验证（本轮完成）**：
   - 打通 KDNET（根因是主机侧 50000 端口被残留 kd.exe 占用）
   - KD 注入字节制造真实 hook（`48`→`49`）
   - `0x11A` 返回 **1**（检出）
   - 驱动**自动恢复**字节，再次检测返回 0
   - 详见 `0x11A正向验证_真实hook检出与恢复_2026-10-29.md`

未完成：

1. **HAL 两个分发表**（`HalPrivateDispatchTable` / `HalDispatchTable`）
   —— 见 `HAL三个分发表_可行性核查_2026-10-29.md`。
   现状：诊断块接口已埋好（env+0x200..0x23F），驱动侧扫描函数已写但
   **判据被实测证伪**（找到的地址与 KD 的 `nt!HalDispatchTable` 不符），
   故未启用。且 `HalAcpiDispatchTable` 在本机 Win10 上**根本不存在**。
2. 文件系统节点的 HTREEITEM 树形外壳（数据层已通，用排序 + 计数替代）
3. 调用链追踪（int2e→SSDT 全链）、消息钩子

> Ring3 inline hook 已从本清单移出——本轮实现并做了正向验证，
> 见 `Ring3InlineHook检测_实现与正向验证_2026-10-29.md`。
>
> 另：inline hook 比对已加入**PE 重定位掩码**（`FeBuildRelocMask`），
> 见 `重定位与动态内存影响_2026-10-29.md`。