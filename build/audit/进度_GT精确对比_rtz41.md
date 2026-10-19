# GT 全表精确对比（RTZ41 实机，1315 个原始非零槽）

用 kd `.writemem` 导出我方整表（144KB），与 `gt_orig_live.bin` 逐槽比较，
内核基址归一后统计。

## 结果

| 类别 | 数量 |
| --- | --- |
| 完全一致 | 996 |
| MISSING（原始非零、我方 0） | **18** |
| EXTRA（原始 0、我方非零） | 1（GT[0x181]，见下） |
| DIFF（两边非零但归一后不同） | 300 |

那 300 个 DIFF 绝大多数是**不同会话的内核/池地址**（本会话内核基址
0xFFFFF80412E00000，原始 dump 是 0xFFFFF8010DA00000），属正常，
不是缺陷。真正意义上的「缺失」只有下面 18 个。

## 18 个 MISSING 槽

| 槽 | 原始值 | 写入者 / 说明 |
| --- | --- | --- |
| 0x179 | 0xFFFFF8010DF6F3B0 | MiniFilterPostWrite / MiniFilterPreCleanup |
| 0x17B | 0xFFFFF8010DFD0B10 | ParseNtKernelDataSectionsV2 0x1400139B7 |
| 0x17D | 0xFFFFF8010E01FAA0 | MiniFilterPostRead / MiniFilterPreWrite |
| 0x18B | 0x5900 | 各 InitEprocessOffsets*（**见下节**） |
| 0x18C | 0x5980 | 同上 |
| 0x18D | 0xD8 | 同上 |
| 0x18E | 0x98 | 同上 |
| 0x197 | 0xFFFFF8010E020A80 | FindKernelDataSectionByData 0x140013E1D |
| 0x198 | 0xFFFFF8010E228F14 | InitImageNotifyCallbackWin7 0x14001377C |
| 0x1A4 | 0x14056F3B0 | MiniFilterPostWrite 0x140014E6B |
| 0x2CA | 0xFFFFF8010DF70CC0 | FindHookTargetDataSection（已诊断到细节） |
| 0x2D5 | 0x1 | InitAllHookSubsystems 0x14001ED6A |
| 0x34E | 0xFFFFF8010DE215E0 | HookSyscallNtDeleteKey 0x14001D953 |
| 0x802 | 0xFFFFF801124C0000 | InitProcessNotify（本会话 td.sys 未装 → 0 属正常） |
| 0x803 | 0x10000 | 同上 |
| 0x912 | 0x1 | FindKernelDataSectionByData 0x140013E2E |
| 0x4474 | 0x5F5FD0 | 未定位 |
| 0x4475 | 0xFFFFF8010DFF5FD0 | 未定位 |

## EXTRA GT[0x181] = 0x5900

原始**也写** 0x181（`FindKernelDataSectionByCode` 0x140013C0B），
只是原始会话里该分支未命中。我方命中并写入了 `NtImageBase + Result`，
但值是 0x5900（小整数），说明 `NtImageBase` 当时为 0 ——
`FindKernelDataSectionByCode` 的成功路径在 `GT[3]==0` 时会写出错误值。
需复核该函数是否应在 `NtImageBase == 0` 时拒绝写入。

## 0x18B-0x18E 的真相（本机 build 19045）

派发逻辑（原码 0x140021440..4CC）：

    build in [0x4A61, 0x4A65]  → call 0x1400244A8  (InitEprocessOffsetsWin10_19041)
    build == 0x47BB            → call 0x140023C2C
    build in {0x4F7C,0x55F0,0x585D,0x5867} → call 0x1400257F0
    其它                        → call 0x1400231DC  (InitEpoch17134)

19045 = 0x4A65 落在第一档，走 `0x1400244A8`。
而该函数**没有**任何写入 0x5900/0x5980 的指令（已全量扫描）。
写 0x5900 的是 0x140022AFC（15063）、0x140023573（17134）、
0x140023F75（18362）、0x1400251AA（10240）、0x140027325（Win81）等 ——
都不在本机派发路径上。

所以原始活体的 0x18B-0x18E **不是 EPROCESS 初始化写的**，
而是由别处（很可能是某个节区扫描器的动态索引 `lea ecx,[base-k]`）
写入。需要继续定位。
