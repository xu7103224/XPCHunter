# RTZ50 剩余差异（EXTRA 已清零）

## EXTRA 0 → 已消除

**GT[0x181] 我方误写的根因**：`xpc_gt_enum.h` 里
    #define GtEprocessField129 GtPeCodeSectionEndVa   /* = 129 = 0x81 */
覆盖了枚举常量 `GtEprocessField129 = 139 (0x8B)`。
于是 `GtEprocessField129 | 0x100` 求值为 **0x181** 而不是 0x18B，
把本该写进 GT[0x18B] 的 0x5900 写到了 GT[0x181]。

修复：把所有 `GtWrite(GtEprocessField129|0x100, …)` /
`GtWrite(GtEprocessField130|0x100, …)` 改为显式槽号 0x18B / 0x18C
（涉及 Win7/Win8/Win81/Win81_Update/10240/14393/15063/17134/18362/
19041/Win11 十一个初始化函数）。实机确认 GT[0x181]=0 且
GT[0x18B]=0x5900、GT[0x18C]=0x5980 仍正确。

## MISSING 6

| 槽 | 原始 | 说明 |
| --- | --- | --- |
| 0x179 | 0xFFFFF8041336F3B0 | MiniFilterPostWrite（离线 ORIG 也不写，需实机断点） |
| 0x1A4 | 0x14056F3B0 | 同上 |
| 0x44 | 0xFFFFE6804331AA80 | `HookSyscallNtSetValueKey` 写 `[rsp+0x40]`（子调用产物）；我方写 0 |
| 0x46 | 0xFFFFE6804331AB00 | 静态扫描无写点（动态索引） |
| 0x4474 | 0x5F5FD0 | 静态扫描**无写点**（原始也靠动态索引） |
| 0x4475 | 0xFFFFF804133F5FD0 | 同上 |

0x44/0x46/0x4474/0x4475 的值都是**会话相关池指针**，
即使原始重新加载也会得到不同值；真正要复刻的是「是否写入」。
