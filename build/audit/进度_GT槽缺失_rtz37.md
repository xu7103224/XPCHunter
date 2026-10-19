# GT 槽缺失进度（RTZ37 实机核对）

## 已完成（实机逐字节一致）

MiniFilter 三扫描器共 9 槽，RTZ37 实机值与原始活体完全一致：

| 槽 | 值 |
| --- | --- |
| 0x332 | 0x6E6E90 |
| 0x333 | 0xFFFFF8010E0E6E90 |
| 0x334 | 0x693ED0 |
| 0x335 | 0xFFFFF8010E093ED0 |
| 0x336 | 0x640 |
| 0x337 | 0xFFFFF8010E3AB890 |
| 0x8EC | 0x693FB0 |
| 0x8ED | 0xFFFFF8010E093FB0 |
| 0x8EE | 0x6E6EB0 |
| 0x8EF | 0xFFFFF8010E0E6EB0 |

## 剩余 20 槽（原始非零、我方为 0）

| 槽 | 原始值 | 写入者（静态扫描） | 备注 |
| --- | --- | --- | --- |
| 0x179 | 0xFFFFF8010DF6F3B0 | MiniFilterPostWrite 0x140014E79 / MiniFilterPreCleanup 0x140015077 | 已重写但实机不命中 |
| 0x1A4 | 0x14056F3B0 | 同上（0x140014E6B / 0x140015069） | 同上 |
| 0x17B | 0xFFFFF8010DFD0B10 | ParseNtKernelDataSectionsV2 0x1400139B7 | |
| 0x17C | 0xFFFFF8010DFC87C0 | FindKernelDataSectionForImageNotify 等 | 已完成（我方 0xFFFFF8010DFC87C0 一致，见下） |
| 0x17D | 0xFFFFF8010E01FAA0 | MiniFilterPostRead 0x140014896 / MiniFilterPreWrite 0x140014A81 | |
| 0x18B | 0x5900 | 各 InitEprocessOffsets* | 本机 build 19045 走 0x1400244A8，该函数不写此槽 |
| 0x18C | 0x5980 | 同上 | 同上 |
| 0x18D | 0xD8 | 仅 Win11 / Win81_Update 写 | 本机路径不写 |
| 0x18E | 0x98 | 仅 Win11 / Win81_Update 写 | 本机路径不写 |
| 0x197 | 0xFFFFF8010E020A80 | FindKernelDataSectionByData 0x140013E1D | |
| 0x198 | 0xFFFFF8010E228F14 | InitImageNotifyCallbackWin7 0x14001377C | |
| 0x2CA | 0xFFFFF8010DF70CC0 | FindHookTargetDataSection 0x14001CC20 | |
| 0x2D3 | 0xFFFFF8010DF6F468 | HookSyscallNtQuerySystemInfo 0x140020078 | |
| 0x2D5 | 0x1 | InitAllHookSubsystems 0x14001ED6A | |
| 0x34E | 0xFFFFF8010DE215E0 | HookSyscallNtDeleteKey 0x14001D953 | |
| 0x802 | 0xFFFFF801124C0000 | InitProcessNotify 0x14001F7BC | |
| 0x803 | 0x10000 | 同上 | |
| 0x817 | 0xFFFFF8010DF6F6F8 | DisableHookProtection 0x14001CDD6 | |
| 0x818 | 0xFFFFF8010DF6F8E0 | DisableHookProtection 0x14001CDF3 | |
| 0x912 | 0x1 | FindKernelDataSectionByData 0x140013E2E | |

## 已核对一致（非缺失）

- 0x17C：我方实机 = 0xFFFFF8010DFC87C0，与原始一致。

## 下一步

按写入者分组逐个复核。优先处理各自**上游输入**也依赖的槽：
- MiniFilterPostWrite（0x179/0x1A4）：需 GT[0x439F]/[0x41C5]/[0x170] 等上游。
- Hook 族（0x2CA/0x2D3/0x34E/0x817/0x818）：需 GT[0x416B]/[0x439F]/[0x42D9]。
- InitProcessNotify（0x802/0x803）：需 GT[0x1F] 等。
- 0x18B-0x18E：本机 build 19045 的原生路径确实不写（需在原始驱动上断点确认）。
