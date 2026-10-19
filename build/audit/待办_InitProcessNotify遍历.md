# 待办：InitProcessNotify 遍历只写出 10/42 槽

## 症状（RTZ37 实机实测）

原始写 42 槽，我方只写 10 槽，且其中 3 个写的是**错误的值**：

| 槽 | 原始 | 我方 | 说明 |
| --- | --- | --- | --- |
| 0x50 | 0xFFFF9A614CD20000 (win32k) | **0xFFFF9D0F26FA8AB0** | 我方值 = **本驱动自己的 DriverObject** |
| 0x51 | 0x8C000 | 0 | |
| 0x52 | 0xFFFFF801127C0000 (fastfat) | 0xFFFF9A614CD20000 | 我方把 win32k 的基址写进了 fastfat 槽 |
| 0x53 | 0x6B000 | 0x8C000 | 同上 |
| 0x87E | 0xFFFFF80110410000 (fltmgr) | 0xFFFF89015E91AA80 | |
| 0x8F4 | 0xFFFF9A614CE10000 (win32kbase) | 0xFFFF9D0F20E8B380 | |
| 0x54/0x55 | ntfs | **一致** | |
| 0x56/0x57 | hal | **一致** | |
| 0x192/0x193, 0x1A1/0x1A2, 0x2D8..0x362, 0x7F8/0x7F9, 0x802/0x803, 0x2F1..0x2FE, 0x309/0x30A, 0x317..0x323 | 悉数非零 | 全 0 | 全部缺失 |

## 关键证据

`GT[1]`（DriverObject）在本会话是 `0xFFFF9D0F26F02E30`（原始活体 dump 里就是这个值）。
`!drvobj RTZ37` 显示我方 DriverObject = `0xFFFF9D0F26FA8AB0`，
**恰等于我方写进 GT[0x50] 的值**。

即：我方在 GT[0x50] 处写入了**自己的 DriverObject**，说明遍历时命中了一个
被误判为 `win32k.sys` 的节点 —— 极可能是遍历起点本身（DriverObject 自身被当作节点，
其 +0x30 恰是 DeviceObject 链表头，+0x60/+0x58 处正好满足比较条件）。

## 差异点（待实机断点确认）

原始 `0x14001EFEF`：
    mov rsi,[rax+0x28]   ; rax = GT[1] = DriverObject → rsi = DriverSection
    mov rbx,[rsi]        ; 首节点 = DriverSection->InLoadOrderLinks.Flink
我方同样写法。但需确认：
  1) DriverSection 布局：`_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks` 在 +0x00，
     `BaseDllName` 在 +0x58（UNICODE_STRING，其 Buffer 在 +0x60）、
     `DllBase` 在 +0x30、`SizeOfImage` 在 +0x40 —— 与代码一致。
     但 `Type` 取的是 `[node+0x58]` —— 那实际是 `BaseDllName.Length`（USHORT），
     不是"类型"！原始正是拿名字长度当分派键，比较长度 = Length>>1，自洽。
  2) 我方可能读到了 `Node+0x58` 之外的东西（若 Node 指针错位）。

## 下一步

1. 在原始驱动上于 `0x14001F3A3`（循环顶）下断，记录 rbx 序列与
   `[rbx+0x58]` / `[rbx+0x60]`，导出真实的模块链遍历顺序。
2. 在同一位置对我方（RTZ37）下断，对比 rbx 序列，定位首次分叉。
3. 特别注意：原始终点判断用 `[rip+0x6df26]` = `MmSystemRangeStart`。

## 环境发现（2026-10-19 追加）

原始驱动（origdrv.sys）加载后**立即自行卸载**（`lm` 显示它在 Unloaded modules 列表）。
其 DriverEntry 有自检逻辑（检测到已有实例/设备名冲突就返回失败）。
但即便如此，它卸载后仍留下设备对象残留：
- 之后用新服务名 + 新文件名（RTZ38 / drv38.sys）再启动我方驱动，
  依旧报 `183 STATUS_OBJECT_NAME_COLLISION`。
- 说明残留的是**设备对象名**（`\Device\...`），不是文件或服务名。
- 解决：重启 guest（可清除设备对象命名空间）。

**结论**：没法在同一 guest 会话里先跑原始、再跑我方做对比。
原始驱动的 GT 值只能从既有的 `gt_orig_live.bin`（同一内核会话）取，
我方则单独跑一次，两边都以“内核基址 + RVA”归一后比较。
