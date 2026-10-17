# InitThreadNotify — 完整逆向规格（原始 0x14001F8E4，长度 0x677）

> 来源：原始驱动反汇编（`build/audit/_dis_InitThreadNotify.txt`，359 条指令）
> ＋ IDA 注释 ＋ **活体 GT 表验证**（`gt_orig_live.bin`）。
> 我方当前实现是约 30 行的桩函数 → 导致 GT 表 **约 20 个槽缺失**（见 `gt_diff_report.txt`）。

## 1. 函数语义

遍历内核模块链表（`GT[1]` = DriverObject → `[+0x28]` = LDR 链表头），对每个
`LDR_DATA_TABLE_ENTRY`：

| 字段 | 偏移 | 含义 |
| --- | --- | --- |
| `[+0x30]` | QWORD | DllBase（映像基址） |
| `[+0x40]` | DWORD | SizeOfImage（**注意是 dword**，读时 `mov edx,[rbx+40h]`） |
| `[+0x50]` | QWORD | 必须非 0（FullDllName/FileName 相关，守卫条件） |
| `[+0x58]` | WORD | 名称字节长度（`movzx eax,word ptr [rbx+58h]`） |
| `[+0x60]` | QWORD | 名称缓冲指针（UNICODE_STRING.Buffer） |
| `[+0x00]` | QWORD | 下一个条目（`mov rbx,[rbx]`） |

循环条件：
- 先判 `rbx <= MmSystemRangeStart` → **直接返回**（退出整函数）
- `rbx == rsi`（回到链表头）→ 返回
- 条目 `[+0x60]==0` 或 `[+0x50]==0` → 跳到 Next 条目

匹配用 `StringCompare3Way(局部UTF16串, entry[+0x60], entry[+0x58]>>1)`，
即**按条目的名称长度**比较（`r8d = eax>>1` 或常数）。命中后：
```
GtWrite(baseIdx, entry[+0x30]);    // DllBase
GtWrite(baseIdx+1, entry[+0x40]);  // SizeOfImage (dword)
Found = 1;  // dil = 1
```

返回值 = `Found`（字节）。

## 2. 名称 → 索引 映射（按长度分派）

按 `entry[+0x58]`（名称字节长度）分支，每个分支内依次比对若干候选名：

| 名称长度 | 候选名 | 基址索引 | 大小索引 |
| --- | --- | --- | --- |
| 0x0C (6字符) | `ms.sys` | 0x917 | 0x918 |
| 0x0E (7字符) | `afd.sys` | 0x8D6 | 0x8D7 |
| 0x10 (8字符) | `disk.sys` | 0x8A8 | 0x8A9 |
| 0x10 (8字符) | `ntoskrnl.exe` | 0x8D0 | 0x8D1 |
| 0x10 (8字符) | `Tm.sys` | 0x8D3 | 0x8D4 |
| 0x12 (9字符) | `dxgkrnl.sys` | 0x8AA | 0x8AB |
| 0x12 (9字符) | `ftlmgr.sys`(空分支注释) | 0x8C1 | 0x8C2 |
| 0x14 (10字符) | `win32k.sys` | 0x8AC | 0x8AD |
| 0x14 (10字符) | `f01000.sys`/`fltdrv.sys` 视版本 | 0x902 | 0x903 |
| 0x16 (11字符) | `subprocsys.sys` | 0x8DA | 0x8DB |
| 0x16 (11字符) | `win32ksgd.sys` | 0x8E0 | 0x8E1 |
| 0x16 (11字符) | `cdrom.sys` | 0x905 | 0x906 |
| 0x18 (12字符) | `win32k.sys`(12字符形态) | 0x8AE | 0x8AF |
| 0x18 (12字符) | `fltmgr.sys` | 0x8C4 | 0x8C5 |
| 0x18 (12字符) | `lsnap.sys` | 0x8DD | 0x8DE |
| 0x1A (13字符) | `win32ksgd.sys`(13字符形态) | 0x91B | 0x91C |

### 版本相关的名字构造（0x14001FAFB `cmp eax,1770h`）
比较 `GT[0x914]`（构建号）：
- `< 0x1770`（Win7 之前）→ 用 `ftdisk`（`740066/690064/6B0073`）
- `>= 0x1770` → 用 `volmgr`（`6F0076/6D006C/720067`）

以及 0x14 长度分支里的 `fldtisksys`/`fltdrv` 变体同理。

## 3. 已解码的 UTF-16 局部名（来自反汇编立即数）

`sec.sys`(实际应为 `seclogon`类，按长度分支取用)、`disk.sys`、`fLdr.sys`(fldr)、
`win32ksgd.sys`、`lsnap.sys`、`fltdrv.sys`、`ftlmgr.sys`、`Tm.sys`、
`afd.sys`、`cdrom.sys`、`f01000.sys`、`i8042prt`、`mgr.`/`t.sys`

> 注：立即数解码受编译器交错存储影响，个别条目需以 IDA 注释（上表）为准。

## 4. 我方需修的点

1. **函数整体重写**：从桩函数改为上述「按长度分派 + 名字比对 + 双索引写入」。
2. `entry[+0x40]` 是 **dword** 读（`mov edx, dword ptr`），写入时零扩展 —— 别写成 qword。
3. 命中即 `Found=1` 但**继续遍历**（`jne 0x14001fba7` 只在回到链表头时退出），
   因此多个驱动可同时命中并写各自索引对。
4. `rbx <= MmSystemRangeStart` 是**整函数提前返回**（不是跳到 Next）。

## 5. 验证方式

改完后：`sc start` → dump `GT[...]` → 与 `gt_orig_live.bin` 比对这一组索引：
0x917/0x918、0x8D6/0x8D7、0x8A8/0x8A9、0x8D0/0x8D1、0x8D3/0x8D4、
0x8AA/0x8AB、0x8C1/0x8C2、0x8AC/0x8AD、0x902/0x903、0x8DA/0x8DB、
0x8E0/0x8E1、0x905/0x906、0x8AE/0x8AF、0x8C4/0x8C5、0x8DD/0x8DE、0x91B/0x91C。