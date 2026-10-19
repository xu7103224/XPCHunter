# 待实现：MiniFilter 三个扫描器（覆盖 9 个缺失 GT 槽）

> 2026-10-19。三者**完全未实现**，且 `SelectMiniFilterDirEnumCallback`
> 还调错了目标。反汇编已存档，可据此逐条实现。

## 1. 分派修正（先做这个）

`SelectMiniFilterDirEnumCallback`（原始 **sub_1400150E4**，
我方 `Minifilter.c` 中的同名函数）原始是三个 tail-call `jmp`：

| 条件 | 原始 jmp 目标 | 语义名 |
| --- | --- | --- |
| build < 0x23F0 | `0x140015A48` | `MiniFilterPreDirEnum` |
| build < 0x2800 | `0x140015F34` | `MiniFilterPreSetInfo` |
| 否则 | `0x1400152D4` | `MiniFilterPreClose` |

**我方现状**：错误地调用 `FindKernelObjectFieldOffsetsWin8/Win10/Win10Early`。
本机 build 19045 → 应走 `MiniFilterPreClose`。

反汇编：`build/audit/_selde.txt`（原始），照抄即可。

## 2. MiniFilterPreClose — sub_1400152D4（486 条指令 / 1908 字节）

反汇编全文：`build/audit/_preclose.txt`

### 入口（6+1 个 GT 输入，全部须非 0）

| GT 槽 | 原始读点 | 我方寄存器 |
| --- | --- | --- |
| 0x20（PE 文件缓冲） | 0x14001530B | rsi |
| 0x21（文件大小） | 0x140015315 | r12d |
| 3（ntoskrnl 基址） | 0x140015327 | rdi |
| 0x8CC | 0x140015334 | r14 |
| 0x900 | 0x140015346 | r15 |
| 0x8CD | 0x140015357 | rbx |
| 0x4459 | 0x140015368 | [rbp-0x78] |

任一个为 0 → 跳 0x1400159F4（收尾）。

### 关键步骤

1. **构造节名 ".PAGE"**：`mov dword [rsp+0x60], 0x4741502E` = ".PAG"，
   `mov dword [rsp+0x64], 0x45` = "E"。即字面量 `".PAGE"`（6 字节）。
2. 调 `FindPESectionByName`（**0x140005C28**，即我方 `FindPESectionByName`）
   求 .PAGE 的 **raw 偏移**；再调 `FindPESectionByNameReturnVa`（**0x140005CB4**）
   求其 **VA**。
3. 扫描区间：起点 = `缓冲 + raw偏移`（r13），终点 = 起点 + min(...)（[rsp+0x68]）。
4. **模式搜索**（循环，0x140015436 起）：找字节序列
   - `48 8D`（lea）且 `[+3]` 的 dword 减去基址后 = 有效 RVA（r14d，[rsp+0x44]）
   - 命中后：若 `[+7]==48 && [+8]==89 && [+0xA]==08`（`48 89 08` = mov [rax],rcx），
     则以 `起点+7` 为缓冲、以计算出的长度为界，**调 InitPESectionReadContext
     （0x140008A7E4）+ ReadPESectionEntry（0x140008A54C）** 解码指令流。
   - 解码循环中对描述符判据（偏移经 desc_offsets.py 可复核）：
     - 类型指针 +0x118 取 [+6]：`0x512` → 判 `[rbp+0x78]`（=偏移 0x88）== 0x40000
       且 `[rbp+0x68]`（=0x78）非 0
     - 类型 `0x547` → 判 `[rbp+0x78] & 0x800000`、`[rbp+0x60]`（=0x70）== 0x1000、
       且等于 GT[0x900]（r15）
5. **写块 1（0x14001569F..6D6）**：
   ```
   GT[0x332] = r14d            ; = 扫描到的目标偏移
   GT[0x333] = r14 + GT[3]     ; + ntoskrnl 基址
   GT[0x8EE] = edi             ; 另一个偏移
   GT[0x8EF] = edi + GT[3]
   ```
6. **写块 2（0x1400157FF..838，结构对称）**：
   ```
   GT[0x334] = ...
   GT[0x335] = ... + GT[3]
   GT[0x8EC] = ...
   GT[0x8ED] = ... + GT[3]
   ```
7. `GT[0x336]`（0x1400158D4）、`GT[0x337]`（0x140015A27）各一处。

### 建议实现方式

先按 `_preclose.txt` 的**控制流骨架**（0x140015436 的大循环 + 三处写块）落成 C，
每个判据的字段偏移用 `desc_offsets.py 0x1400152D4 0x780` 复核
（已确认为：+0xF0 推进、+0x118 类型指针、+0x88、+0x70、+0x78、+0x40）。

## 3. MiniFilterPreDirEnum — sub_140015A48（1257 字节）

写 GT[0x332-0x337]（与 PreClose 重叠）。反汇编：
`python build/audit/show_asm.py 0x140015A48 0x500 build/audit/_mpde.txt`

已确认判据（desc_offsets.py）：
- 第一轮：+0x88 == 0x800000、+0x70 == 0x1000
- 第二轮：+0x88、+0x78
写槽点（原始）：0x32E/0x330/0x32F/0x331（第一段）、0x332/0x333、
0x334/0x335、0x336、0x337。

## 4. MiniFilterPreSetInfo — sub_140015F34（1231 字节）

判据：+0xF0 推进、+0x40（`cmp eax,[rbp+0x10]`）、+0x40 == 0xFF8。

## 验收

实现后：
1. `cmd //c "build\build.bat Release x64"` → 无错误
2. `python build/audit/sync_addrs.py && python build/audit/oracle_fsn_table_diff.py`
   → 必须 464 条全同
3. 实机：sign → push → VNC 提升运行 → `STATE: 4 RUNNING`
4. kd 读 GT：0x332-0x337 / 0x8EC-0x8EF 应非 0，且与 `gt_orig_live.bin` 同槽
   的**低 32 位值**一致（高 32 位含各自内核基址，需按 kbase 归一比较）