# 0x047 块 2/3：崩溃点锁定在 ReadPESectionEntry+0xB9（2026-10-27）

## 铁证（kd_capture_fault 一次捕获）

```
*** Fatal System Error: 0x0000003b
    (0x00000000C0000005, 0xFFFFF80149888329, 0xFFFF818F1DA75760, 0)
faulting_instruction:
    XPCHunterDrv+0x58329:  movzx eax, byte ptr [r9]      ← r9 野指针
```
- `0x58329 − 0x58270 = 0xB9`，即 **`ReadPESectionEntry` 内部偏移 +0xB9**
- 崩溃发生时的调用链（`kd_log_tail` 记录，多次命中可见）：
```
XPCHunterDrv+0x58270   ← ReadPESectionEntry
XPCHunterDrv+0x83efd   ← EnumerateProcessCallbackContext 第1层循环（0x12C 轮处）
XPCHunterDrv+0x58270   ← ReadPESectionEntry（再次）
XPCHunterDrv+0x81b06   ← EnumerateProcessCallbackContext
XPCHunterDrv+0x58270   ← ReadPESectionEntry
XPCHunterDrv+0x81929 / +0x817b7 / +0x81629 ← 同一函数多处调用点
XPCHunterDrv+0x3ca70   ← EnumerateProcessCallbackContext 入口
```
即：**`EnumerateProcessCallbackContext` 确实在反复调用 `ReadPESectionEntry`，
而后者在解析这批节区描述符时崩了。**

## 这解释了此前所有现象

| 现象 | 解释 |
|---|---|
| `GT[0x2B8]/[0x2BA]/[0x2BB]` 恒为 0 | 扫描根本没跑完就崩了（异常被上层吞掉或循环中断） |
| 我加的 4 个字段诊断变量全 0 | 同上 —— 第 1 层一次都没走到判据 |
| 多次实现块 2/3 遍历时 BSOD | 不是遍历代码的问题，是更底层的解码器崩 |
| `FindSsdtTableAddresses` 读到垃圾字段（`AlignmentValue=0x500BE9`） | 同一个解码器缺陷 |

## 根因定位：审计项 P0-1

`PEDecoder.c:185` 的 `ReadPESectionEntry` 头部自述：
```c
// 注意：原始驱动把这三个值分别写入描述符的 +0x110/+0x10/+0x18，本重建的目标
// 偏移尚未按原始布局改正（见审计报告 P0-1 的 0x120 描述符布局表）。
```
偏移写错 → 后续 handler 把错误位置的内容当"表条目指针" →
`dispatch` 时 `movzx eax, byte ptr [r9]` 解引用野指针 → AV。

**这一处就是 3 条命令 + 至少 4 条命令（0x0F4/0x0F6/0x10B/0x047）的共同阻塞点。**

## 修复方案（下一轮唯一入口）

1. 打开原版 `ReadPESectionEntry`（**0x14008A54C**）及其子解码器
   （`DispatchInstructionDecode` 各 handler）的反汇编；
2. 逐条核对 `+0x10 / +0x18 / +0x110`（Param6/Param7/ExtraField 的目标偏移）
   以及操作数记录区 `+0x30/+0x68/+0xA0`（3×0x38）内各字段的下标；
3. 修正 `PEDecoder.c` 的 `DEC_CTX_*` 定义与对应 SET_ 调用；
4. 回归 `0x0FF`（当前 7384 B / 0 差异，它只用外层字段，改后必须仍一致）；
5. 再验 `GT[0x2B8]/[0x2BA]/[0x2BB]` 非 0 → 块 2/3 自动出数据。

## 本轮 kd 操作要点
- `bp <addr> "kb 2; g"` 自恢复断点，配合 `kd_log_tail` 读调用链
- `kd_capture_fault` 需要目标停在 bugcheck 且未 `kd_go`
- 崩溃后 **不要 kd_go / kd_detach**（会完成崩溃流程并丢现场）