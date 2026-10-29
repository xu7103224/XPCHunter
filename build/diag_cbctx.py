# 给 EnumerateProcessCallbackContext 加阶段计数，定位 GT[0x2B8] 未写入的位置
p = 'XPCHunterDrv/src/kernel/Minifilter.c'
s = open(p, encoding='utf-8').read()

# 1) 入口守卫后
old_entry = """    if (CurrentOffset
        && CurrentOffset < (ULONG)NtoskrnlBase
        && SectionBase
        && (ULONG)SectionBase < (ULONG)NtoskrnlBase
        && SectionSize
        && NtoskrnlBase
        && NtoskrnlImageBase)
    {"""
new_entry = """    /* [diag] 1=entered 2=guards passed 3=hit 0x512/+0x50==0x40/+0x58==2/+0x90==4
       4=hit 2nd level (0x512/+0x50==0x40/+0x58==1/+0x88==0x40000)
       5=wrote GT[0x2B8]  6=seg2 hit  7=wrote GT[0x2BA] */
    g_DiagCbCtxStage = 1;
    g_DiagCbCtxFileSize = (ULONG)CurrentOffset;
    if (CurrentOffset
        && CurrentOffset < (ULONG)NtoskrnlBase
        && SectionBase
        && (ULONG)SectionBase < (ULONG)NtoskrnlBase
        && SectionSize
        && NtoskrnlBase
        && NtoskrnlImageBase)
    {
        g_DiagCbCtxStage = 2;"""
assert old_entry in s, "entry anchor"
s = s.replace(old_entry, new_entry, 1)

# 2) 第一段命中处（+0x90==4 之后）
old_hit1 = """            if (*(ULONG *)((PUCHAR)SectionEntry + 0x90) != 4)
                continue;"""
new_hit1 = """            if (*(ULONG *)((PUCHAR)SectionEntry + 0x90) != 4)
                continue;
            if (g_DiagCbCtxStage < 3) g_DiagCbCtxStage = 3;"""
assert old_hit1 in s, "hit1 anchor"
s = s.replace(old_hit1, new_hit1, 1)

# 3) 第二段命中处（+0x88==0x40000 之后）
old_hit2 = """            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) != 0x40000)
                continue;"""
new_hit2 = """            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) != 0x40000)
                continue;
            if (g_DiagCbCtxStage < 4) g_DiagCbCtxStage = 4;"""
assert old_hit2 in s, "hit2 anchor"
s = s.replace(old_hit2, new_hit2, 1)

# 4) 写入 GT[0x2B8] 之前
old_w = """            GtWrite((GLOBAL_TABLE_INDEX)GtKernelDataField38, NtoskrnlImageBase + ComputedRva);"""
new_w = """            g_DiagCbCtxStage = 5;
            GtWrite((GLOBAL_TABLE_INDEX)GtKernelDataField38, NtoskrnlImageBase + ComputedRva);"""
assert old_w in s, "write anchor"
s = s.replace(old_w, new_w, 1)

open(p, 'w', encoding='utf-8').write(s)
print("diag added")