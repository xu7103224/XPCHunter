# 最终状态（RTZ51 实机，与 19045 同版本原始基线对比）

## GT 全表对比

| 类别 | RTZ37（本轮起点） | RTZ51（当前） |
| --- | --- | --- |
| MISSING（原始非零、我方 0） | 18 | **4** |
| EXTRA（原始 0、我方非零） | 1 | **0** |

## 剩余 4 个 MISSING

| 槽 | 原始值 | 写入者 | 说明 |
| --- | --- | --- | --- |
| 0x179 | 0xFFFFF8041336F3B0 | MiniFilterPostWrite | 离线 ORIG 也不写（守卫依赖 GT[0x439F]/[0x41C5] 与扫描命中），需实机断点 |
| 0x1A4 | 0x14056F3B0 | MiniFilterPostWrite | 同上 |
| 0x4474 | 0x5F5FD0 | 未知 | 静态扫描**无任何写入点**（原始亦然），疑为动态索引或运行期外部写入 |
| 0x4475 | 0xFFFFF804133F5FD0 | 未知 | 同上；0x4475 = 模块基址 + 0x5F5FD0 |

## 本轮（一次会话）修复清单

| 修复 | 影响槽 | 证据 |
| --- | --- | --- |
| 解码器 reg/rm/mod 改从 +0xDC 取 | 0x17B、0x2CA（并保住 0x197/0x912、三扫描器、0x817/0x818） | 离线 IDENTICAL |
| HookSyscallNtQuerySystemInfo 重写 | 0x2D3 | 实机 RVA 一致 |
| DisableHookProtection 的 SectionOffset 初值 | 0x817、0x818 | 实机 RVA 一致 |
| CheckObjectTypeFlag 补 (>>8) 异或 | 0x81B..0x81E | 实机全等 |
| CheckVmxEnabled 改读 CR4.VMXE | 0x2D5 | 实机全等 |
| FindKernelDataSectionByData 入口 GT 纠错 | 0x197、0x912 | 离线 IDENTICAL |
| InitImageNotifyCallbackWin7 重写 | 0x198 | 离线 IDENTICAL |
| InitEprocessOffsetsWin10_18362 补 5 槽 | 0x18B..0x18E、0x69 | 实机全等 |
| HookSyscallNtDeleteKey 无界循环 + 0x1000 窗口 | 0x34E | 离线 IDENTICAL |
| InitProcessNotify 名字 td.sys→tdi.sys | 0x802、0x803 | 实机全等 |
| enum 宏别名导致的 0x181 误写 | EXTRA 清零 | 实机全等 |
| Registry.c 宏别名（0x18B/0x18C） | 0x44、0x46 | 实机全等 |

## 回归门（全部通过）

    build\build.bat Release x64          → Build complete，0 error 0 warning
    oracle_fsn_table_diff.py             → 464 条全同
    oracle_trace_fkpsbt.py               → ORIG/MINE 均 0x41/0x18
    oracle_minifilter3.py                → PreClose 9 / DirEnum 2 / SetInfo 0，全 IDENTICAL
    oracle_pnkds2 / fhtds / fkdsbd / dhp / ndk2 / iinw7 → 全 IDENTICAL

## 实机

    sc start RTZ51 → STATE: 4 RUNNING
