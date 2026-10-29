# 修正 EnumerateProcessCallbackContext 的 InitPESectionReadContext 参数
# 原版 0x14003EB92..0x14003EBBF：
#   edx = r12d                    ; GT[0x21] (镜像大小)
#   ecx = r14d                    ; GT[0x42D0] CurrentOffset
#   rcx += r12                    ; rcx = CurrentOffset + SectionBase(GT[0x43A8]=rbx? 见下)
#   edx -= ecx                    ; edx = GT[0x21] - (CurrentOffset + SectionBase)
#   edx += edi                    ; edx += (ULONG)GT[0x20] 的低 32 位
#   r8d = 2, r9d = 0, var_1E0 = 0, var_1E8 = 0, var_1F0 = -1
# 注意：0x14003EBBA 的 `add rcx, r12` 里 r12 在函数序中是 GtRead(0x20) 的结果、
#   r14 是 GtRead(0x42D0)。而 SectionBase(GT[0x43A8]=rbx) 用于另一处。
#   实测四槽：GT[0x20]=0xFFFFC00314400000 GT[0x21]=0xAB2000
#             GT[0x42D0]=0x823260       GT[0x43A8]=0x185F0
#   原版 Base = CurrentOffset + (ULONG)GT[0x20] = 0x823260 + 0x14400000
#   原版 Size = GT[0x21] - Base = 0xAB2000 - 0x144823260  (32 位回绕)
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
        /* [2026-10-27 修正] 按原版 0x14003EB92..0x14003EBBF 精确还原：
             Base = (ULONG)SectionSize + CurrentOffset        ; rcx = r14 + r12
             Size = (ULONG)NtoskrnlBase - (ULONG)Base + ...   ; edx = r12d - ecx
           旧实现用 (SectionBase + CurrentOffset) 作 Base、GT[0x21]-CurrentOffset 作
           Size，与原版量纲不符 → 解码上下文边界错误 → ReadPESectionEntry
           读到缓冲区外，在 +0xB9 处解引用野表项指针（kd 捕获的 AV）。
           原版签名的参数顺序：InitPESectionReadContext(Base, Size, Mode, P5, Extra, P6, P7, Ctx)
           其中 Base 由 r14(CurrentOffset)+r12(GT[0x20]低32位) 组成。 */
        InitPESectionReadContext(
            (__int64)((ULONG)SectionSize + CurrentOffset),
            (ULONG)((ULONG)NtoskrnlBase - ((ULONG)SectionSize + CurrentOffset)),
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