# 追加块 2/3 真正根因到文档
p = 'docs/reversing/剩余四条命令状态与下一步_2026-10-27.md'
s = open(p, encoding='utf-8').read()

s += """

---

## 8. 0x047 块 2/3 的真正根因（2026-10-27，kd 实测确认）

### 8.1 原版/复刻槽值对比（跑完 0x047 后）

| 槽 | 原版 OGT | 复刻 XPCHunterDrv |
|---|---|---|
| GT[0x2B8] | 0xFFFFF80144460920 | **0** |
| GT[0x2B9] | 0 | 0 |
| GT[0x2BA] | 0xFFFFF80144464E6C | **0** |
| GT[0x2BB] | 0xFFFFF8014444AA70 | **0** |

原版这些槽在懒加载后都有值；复刻全 0，于是块 2 一进入
`if (List2 && Size2)` 就失败退出。

### 8.2 槽的真实含义（kd 符号解析）
```
GT[0x2BA] = 0xFFFFF80144464E6C = nt!CmpCallBackCount   <- 注册表回调计数
GT[0x2B8] -> [0xFFFFC0030A91D7A0, 0xFFFFC0030A91D7A0]  <- 空链表头（Flink==Blink）
GT[0x2BB] -> 另一个链表头（Flink/Blink 均有效）
```
即 **块 2 = 注册表回调、块 3 = 另一个回调链表**，与 SSDT 无关。

### 8.3 为什么复刻是 0（与 §6 同一根因）
GT[0x2B8] 的唯一写入者是 `Minifilter.c:8589`
（`EnumerateProcessCallbackContext`，原 0x14003EAA8），
其筛选条件读的正是**同一套 0x120 描述符字段**：
```
+0x50 == 0x40      +0x58 == 1        +0x88 == 0x40000
+0x78 -> RVA 基值   +0xF0 -> 条目长度  +0x118 -> 类型指针（+6 必须 0x558）
```
这与 `FindSsdtTableAddresses` 用的是同一族字段。§6 已确认
**0x120 描述符布局从未按原版改正**（PEDecoder.c 注释自证，审计 P0-1）。
`FindSsdtTableAddresses` 我用"实测 + 运行指针"绕过了，
但 `EnumerateProcessCallbackContext` 没有绕过，所以 GT[0x2B8] 一直是 0。

### 8.4 因此块 2/3 的正确修法
**不是**改链表遍历代码（那部分照原版写的，方向没错；两次 BSOD 是因为
GT[0x2B8] 为 0 时走到了不安全的兜底路径）。真正要做的是
**让 GT[0x2B8] 被正确写入**：按原版 0x14003EAA8 + P0-1 布局表修正
`Minifilter.c` 的 `EnumerateProcessCallbackContext` 中那 6 个字段偏移，
使其能命中类型 0x558 的三层 PE 节区并算出 RVA。

### 8.5 实施顺序（下一轮）
1. 先修 §8.4 的字段偏移 —— 这同时会修复 0x0F6/0x0F4/0x10B 等
   依赖同族扫描的命令；
2. 验证 GT[0x2B8]/[0x2BA]/[0x2BB] 非 0；
3. 块 2/3 的遍历代码保持不动（方向正确），只需保证 GT[0x2B8] 为 0 时
   不要误入危险路径（`Size2` 与 `MmIsAddressValid` 前置判断已在现码里）。
"""

open(p, 'w', encoding='utf-8').write(s)
print("ok")