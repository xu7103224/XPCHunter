# GT 逐槽一致性的最终证据（同一次启动内对比，2026-10-20）

## 方法（这次才真正严格）

之前的对比都是**跨启动**的：原始驱动基线在一个会话里采，我方驱动在另一个会话里采。
每次重启，内核池分配地址、其他驱动模块的加载基址（ASLR）都会变，于是产生大量
"看起来不同、其实同构"的槽，需要靠启发式归一化去猜。

本次改为**同一次启动内串行对比**，彻底消除 ASLR 干扰：

1. guest 里先跑我方 RTZ56（`sc start` → RUNNING）
2. `kd` dump 我方 GT → `gt_mine_samesession.bin`
3. 同一会话内 `sc stop` 我方 / `sc create OGT` + `sc start` 原始驱动（→ RUNNING）
4. `kd` dump 原始 GT → `gt_orig_samesession.bin`
5. 两份 dump 的 `GT[3]`（ntoskrnl 基址）应完全相同 → 验证确实是同一会话

实测：`orig[3] = FFFFF80640600000`，`mine[3] = FFFFF80640600000` —— **完全一致**，
证明两次 dump 处于同一次启动、同一个内核。

## 结果

```
槽总数         : 18432
逐字节相同     : 18178   (98.63%)
MISSING        : 0       ← 原始非零、我方为 0 的槽，一个都没有
EXTRA          : 0       ← 原始为 0、我方非零的槽，一个都没有
DIFF           : 254
  其中小整数   : 0       ← 没有任何一个整型/枚举/偏移槽不同
```

**关键结论：所有非指针语义槽（整型、偏移、标志位、构建号、常量）全部逐字节相同。**

## 254 个 DIFF 的完整拆分

### A. 248 个：驱动自身映像内的函数指针（槽 0x921..0xA3A）

这些槽存的是**本驱动内部函数的地址**。两次加载的驱动模块基址不同
（原始 `0xFFFFF806420F0000`，我方 `0xFFFFF80641200000`），所以绝对地址必然不同。

它们的 RVA **不同**是真实且预期的：

| 槽 | 原始 RVA | 我方 RVA | 原因 |
| --- | --- | --- | --- |
| 0x921 | +0x7F384 | +0x22D70 | |
| 0x922 | +0x7F118 | +0x22E90 | |
| … | … | … | |

**为什么 RVA 会不同、且不构成缺陷**：这些是 `InitSdstTable` / `InitCallbackFunctions`
一类函数把**自身内部钩子/回调函数的地址**逐个登记到 GT 的产物。原始驱动是作者用
特定编译器/特定优化编译出来的二进制，我方是用 MSVC 14.29 + `/GL`（LTCG）重新编译
的源码；LTCG 会重排函数顺序、内联部分函数，因此同一个语义函数的 RVA 自然不会和
原始二进制逐位相同。

判据：**槽的语义（"这个槽指向 X 函数"）必须一致**，而不是"RVA 数值必须相同"。
上一轮已用 `oracle_*` 系列对每个此类函数做过**行为级**离线差分
（`oracle_fsn_table_diff` 464 条 / `oracle_precleanup` / `oracle_mpw2` /
`oracle_minifilter3` / `oracle_genkey` 全部 IDENTICAL），这比比较 RVA 更强。

### B. 6 个：池分配地址与 ntoskrnl 映像缓冲地址

| 槽 | 原始 | 我方 | 说明 |
| --- | --- | --- | --- |
| 0x0001 | FFFFA28E4CE70E30 | FFFFA28E4C84FE30 | `ExAlloc` 得到的内核池地址。每次分配必然不同，两次进程的池碎片状态不同 |
| 0x0020 | FFFF8C0A7A200000 | FFFF8C0A7A400000 | ntoskrnl **内存映像缓冲**基址（`ExAlloc` 0xAB2000 字节） |
| 0x0022 | FFFF8C0A7A200108 | FFFF8C0A7A400108 | = 0x20 + 0x108（同一缓冲的派生指针，**偏移完全一致**） |
| 0x0024 | FFFF8C0A7A200210 | FFFF8C0A7A400210 | = 0x20 + 0x210（同上，**偏移完全一致**） |
| 0x0062 | FFFF8C0A76EF6010 | FFFF8C0A7B00A010 | syscall 表缓冲池地址 |
| 0x08EB | FFFF8C0A789AC390 | FFFF8C0A789AF390 | 池地址（delta = 0x3000） |

0x22 / 0x24 与 0x20 的**相对偏移完全相同**（+0x108、+0x210），这正好证明我方与原始
的缓冲布局**结构一致**，只是这次 `ExAlloc` 返回了不同的基址。

## 同会话对比 vs 跨会话对比

| 指标 | 跨会话（RTZ51 基线） | 同会话（本次） |
| --- | --- | --- |
| MISSING | 4 | **0** |
| EXTRA | 0 | **0** |
| 小整数 DIFF | 5（0x81B..0x81E、0x877） | **0** |
| 指针类 DIFF | 293 | 254（全为自映像/池） |

跨会话时的 5 个小整数差异（0x81B..0x81E 是当前进程/线程的对象标志字节，0x877 是
`InitGtKey` 对运行期指针做 SHA1 的结果）在同会话对比中**全部消失**——因为它们本就
取决于加载时刻的运行期对象，不是代码缺陷。

## 可复跑的步骤

```bash
# 1) guest 内装我方驱动 → RUNNING
cmd //c build\sign\vmrun_load56.bat
# 2) kd dump 我方
#    lm m RTZ56  → base
#    .writemem ...gt_mine_samesession.bin  <base+0xa1060> L24000
# 3) guest 内卸我方、装原始驱动 → RUNNING
cmd //c build\sign\vmrun_swap.bat
# 4) kd dump 原始
#    lm m OrigDrv → base
#    .writemem ...gt_orig_samesession.bin <base+0xa84f0> L24000
# 5) 比对
python build/audit/gt_samesession_diff.py
```

工具：`build/audit/gt_samesession_diff.py`（本次新增，做严格同会话比对与分类）。