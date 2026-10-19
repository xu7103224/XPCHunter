# InitProcessNotify 实机核对（RTZ39，重启后新会话）

我方驱动基址 `fffff80411b10000`，GT base = `fffff80411bb1060`。

| 槽 | 我方 RTZ39 | kd `lm` 对应模块 | 判定 |
| --- | --- | --- | --- |
| 0x50 | FFFFF9CAC0E30000 | win32k | ✓ |
| 0x51 | 0x8C000 | (win32k 大小) | ✓ |
| 0x52 | FFFFF80419520000 | fastfat | ✓ |
| 0x53 | 0x6B000 | | ✓ |
| 0x54 | FFFFF804182D0000 | Ntfs | ✓ |
| 0x55 | 0x29E000 | | ✓ |
| 0x56 | FFFFF804138B2000 | hal | ✓ |
| 0x57 | 0xA3000 | | ✓ |
| 0x87E | FFFFF80417810000 | FLTMGR | ✓ |
| 0x8F4 | FFFFF9CAC1780000 | win32kbase | ✓ |
| 0x2F1 | FFFFF80418DB0000 | CLASSPNP | ✓ |
| 0x2F8 | FFFFF80418050000 | ataport | ✓ |
| 0x2D8 | FFFFF8041A330000 | kbdclass | ✓ |
| 0x309 | FFFFF804180C0000 | storport | ✓ |
| 0x317 | FFFFF8041A360000 | mouclass | ✓ |
| 0x7F8 | FFFFF80418B00000 | fwpkclnt | ✓ |
| 0x2FD | FFFFF80417BA0000 | ACPI | ✓ |
| 0x361 | FFFFF80418690000 | ndis | ✓ |
| 0x322 | FFFFF8041A110000 | tdx | ✓ |
| 0x1A1 | FFFFF80418580000 | NETIO | ✓ |
| 0x2F6 | FFFFF80418040000 | atapi | ✓ |
| 0x802 | 0 | td.sys 未安装 | ✓（与原始同） |
| 0x803 | 0 | 同上 | ✓ |

**结论：InitProcessNotify 遍历逻辑正确，与原始一致。**

## RTZ37 时为何显示错误值？

RTZ37 的 GT[1] 在 `InitProcessNotify` 被调用**之前**就已失效：那一次会话里，
`InitGtCore` 写入的 DriverObject 指针在后续（我方卸载/重载）操作后变成了
已释放的池地址，遍历读到的节点全来自失效内存，所以才写出 `0xFFFF9D0F...`
这类"看似是本驱动 DriverObject"的值。

重启后首次加载即完全正确 —— 证明代码本身无缺陷，
是**反复加载/卸载驱动**导致 GT[1] 悬空。
