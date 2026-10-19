# 剩余缺陷清单（基于 19045 真基线，RTZ42 状态）

## A. MISSING 17 槽（0x2D5 已在 RTZ42 修复）

| 槽 | 原始值 | 写入者 | 状态 |
| --- | --- | --- | --- |
| 0x179 | 0xFFFFF8041336F3B0 | MiniFilterPostWrite | 待修 |
| 0x17B | 0xFFFFF804133D0B10 | ParseNtKernelDataSectionsV2 | 待修 |
| 0x17D | 0xFFFFF8041341FAA0 | MiniFilterPostRead / PreWrite | 待修 |
| 0x18B-0x18E | 0x5900/0x5980/0xD8/0x98 | InitEprocessOffsetsWin10_18362 族 | 待修 |
| 0x197 | 0xFFFFF80413420A80 | FindKernelDataSectionByData | 待修 |
| 0x198 | 0xFFFFF80413628F14 | InitImageNotifyCallbackWin7 | 待修 |
| 0x1A4 | 0x14056F3B0 | MiniFilterPostWrite | 待修 |
| 0x2CA | 0xFFFFF80413370CC0 | FindHookTargetDataSection | 已诊断（第二段只解一轮） |
| 0x34E | 0xFFFFF804132215E0 | HookSyscallNtDeleteKey | 待修 |
| 0x802/0x803 | 0xFFFFF8041A140000 / 0x10000 | InitProcessNotify | **原始在有 td.sys 时写；本机 19045 原始也写了** → 说明 td.sys 在 19045 上存在（模块名可能是 TDI） |
| 0x912 | 0x1 | FindKernelDataSectionByData | 待修 |
| 0x4474/0x4475 | 0x5F5FD0 / 0xFFFFF804133F5FD0 | 未定位 | 待修 |

## B. EXTRA 1 槽

**GT[0x181] 我方=0x5900，原始=0**
写入者 `FindKernelDataSectionByCode`（0x140013C0B），公式
`GT[0x181] = Result + GT[3]`（`0x140013C10: add rdx,rbx`，rbx=GT[3]）。
我方写成了 0x5900（纯偏移），说明**调用时刻 GT[3] 仍为 0**，
而原始在同刻未命中该分支（解码/候选不同）。需查该函数的调用时机。

## C. 真实 DIFF（归一后仍不同，非地址漂移）

| 槽 | 原始 | 我方 | 判定 |
| --- | --- | --- | --- |
| 0x1E0 | 0x5E00158 | 0x56697974 | **不是缺陷**：`GenerateEncryptionKey` 每次随机 |
| 0x1E1 | 0xCF | 0x12 | **不是缺陷**：由 0x1E0 派生 |
| 0x81B | 0xC | 0xBF | **真实缺陷**：见下 |
| 0x81C | 0x3 | 0x52 | 同上 |
| 0x81D | 0x2A | 0x3E | 同上 |
| 0x81E | 0x29 | 0xA7 | 同上 |

### 0x81B-0x81E 的真正来源

`InitEprocessOffsetsWin10_18362` 在 `0x14002433C..35E` 把 0x81B-0x81E
**全部写 0**（`xor edx,edx`）。而原始基线里是非零小整数，
说明它们由运行时的 `ValidateObjReferences`（0x14001C397）写入。
我方该函数算出的值（0xBF/0x52/0x3E/0xA7）与原始（0xC/0x3/0x2A/0x29）不符
→ `ValidateObjReferences` 的字段推导逻辑有误。

## 已验证完成（RTZ42 实机）

- GT[0x2D5] = 1（CheckVmxEnabled 改为 CR4.VMXE）
- GT[0x2D3]（HookSyscallNtQuerySystemInfo 重写）
- GT[0x817]/[0x818]（DisableHookProtection 的 SectionOffset 初值）
- GT[0x332..0x337]、[0x8EC..0x8EF]（MiniFilter 三扫描器）
- GT[0x50..0x57]、[0x87E]、[0x8F4..0x8F7]、[0x192..0x362] 等 21 组模块槽
