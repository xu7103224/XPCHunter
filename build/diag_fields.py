# 在 EnumerateProcessCallbackContext 第1层判据前 dump 4 个字段
p = 'XPCHunterDrv/src/kernel/Minifilter.c'
s = open(p, encoding='utf-8').read()

old = """            if (Type == 0x545)                                    // 1349：结束
                break;
            if (Type != 0x512)                                    // 非 1298：下一轮
                continue;
            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40)
                continue;"""
new = """            if (Type == 0x545)                                    // 1349：结束
                break;
            /* [diag] 记录首批类型 0x512 条目的四个判据字段 */
            if (Type == 0x512 && g_DiagCbCtxFileSize == 0)
            {
                g_DiagCbCtxFileSize = 0xCAFE0000u | (ULONG)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0xFF);
                g_DiagCbCtxStage    = (ULONG)(*(ULONG *)((PUCHAR)SectionEntry + 0x58) & 0xFFFF);
                g_DiagOpenStage     = (ULONG)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) & 0xFFFF);
                g_DiagOpenStatus    = (LONG)(*(ULONG *)((PUCHAR)SectionEntry + 0x90) & 0xFFFF);
            }
            if (Type != 0x512)                                    // 非 1298：下一轮
                continue;
            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40)
                continue;"""
assert old in s, "anchor"
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8').write(s)
print("ok")