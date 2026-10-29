# 修正 EnumerateProcessCallbackContext 的 Base 槽（kd 实测确定）
# kd 实测（我方驱动，InitPESectionReadContext 入口断点）：
#   rcx(Base) = 0xFFFF9D02D192DA20
#   rdx(Size) = 0x00000000009845E0
#   r8        = 0x000000000012DA20
# 同刻 GT 槽：
#   GT[0x20] = 0xFFFF9D02D1800000   GT[0x21] = 0xAB2000
#   GT[0x42D0] = 0x12DA20（循环内被改写；初始 0x823260）
#   GT[0x43A8] = 0x185F0
# 验证：
#   Base = GT[0x20] + GT[0x42D0] = 0xFFFF9D02D1800000 + 0x12DA20 = 0xFFFF9D02D192DA20 ✓
#   Size = GT[0x21] - GT[0x42D0] = 0xAB2000 - 0x12DA20           = 0x9845E0          ✓
# 我方原实现用 GT[0x43A8](SectionBase) 作 Base → 错误；Size 公式本来就对。
p = 'XPCHunterDrv/src/kernel/Minifilter.c'
s = open(p, encoding='utf-8').read()

old = """        g_DiagCbCtxStage = 2;
        InitPESectionReadContext(
            (__int64)(SectionBase + CurrentOffset),
            (ULONG)NtoskrnlBase - CurrentOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);"""

new = """        g_DiagCbCtxStage = 2;
        /* [2026-10-27 kd 实测修正] 在原版/我方同位置断点读到：
             rcx(Base) = GT[0x20] + GT[0x42D0]
             rdx(Size) = GT[0x21] - GT[0x42D0]
           其中 GT[0x20] 是展开镜像的**基址**（0xFFFF9D02D1800000 这类，
           不是大小），GT[0x21] 才是镜像大小，GT[0x42D0] 是节区偏移。
           旧实现把 GT[0x43A8](SectionBase) 当 Base → 指向错误内存，
           解码器在 +0xB9 处读到野表项指针（kd 捕获的 AV，
           且正是它导致 GT[0x2B8]/[0x2BA]/[0x2BB] 永远写不进去）。 */
        InitPESectionReadContext(
            (__int64)(SectionSize + CurrentOffset),
            (ULONG)NtoskrnlBase - CurrentOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);"""

assert old in s, "anchor not found"
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8').write(s)
print("ok")