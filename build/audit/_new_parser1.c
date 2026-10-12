// ParseRsdsDebugInfo — 扫描 PE 数据区，定位 CodeView(RSDS) 记录并登记到导出表
// 对应原始驱动 0x140039D5C（491 字节）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— 该函数是 _FINAL_GAP.json 的
//   A_definite_missing（源码中此前完全缺失，导致 InitProcessContextExportTableWin7
//   装入后 LNK2001）。代码内标注 `L_<地址>`。
//
// 【帧定基（序言 + DecodeUnicodeChar 输出结构反推，已定案）】
//   序言：push rbp,rsi,rdi,r12,r13,r14,r15(0x38) → lea rbp,[rsp-0x27] → sub rsp,0xC0
//   故 rbp = 入口 rsp - 0x5F。
//   **输出结构不是 0x120 描述符**，而是 `DecodeUnicodeChar`(0x140010EAC) 的
//   0x30 字节输出体。由该函数的实现（Utf8Decoder.c:351）逐字段对照，基址 = rbp-0x61：
//     +0x00 WORD  magic(0x404)      +0x08 BYTE  FlagsByte 位分解(取 bit3..5)
//     +0x0C DWORD 解码中间量        +0x10 DWORD 解码中间量
//     +0x18 DWORD DecodeResult=指令长度   +0x28 QWORD → 类型码表指针
//   反汇编实测读取 `[rbp-0x49]/[rbp-0x39]/[rbp-0x55]/[rbp-0x51]/[rbp-0x59]`
//   依次等于 `desc+0x18/+0x28/+0x0C/+0x10/+0x08` —— **五处全部吻合**，基址定案。
//   （此前按 0x120 描述符惯例反推会得到低于栈底的荒谬地址，故曾判"无法定案"。）
//
// 【算法】
//   ① Loaded = GtRead(0x8C1)，为 0 即返回 0；
//   ② 读 PE 头 e_lfanew；EntryPoint=[nt+0x28]、ImageBaseVal=[nt+0x30]；
//      要求 EntryPoint < ImageSize 且 EntryPoint+0x1000 < ImageSize；
//   ③ 第一轮（最多 0x1E 次）：逐条 DecodeUnicodeChar 解析指令，指针按"指令长度"
//      推进；当类型码表首项 == 0x10CE 且算出的 RVA 合法时，记录该 RVA 并跳出；
//   ④ 第二轮：从该 RVA 起，以 0x1000 为窗口继续逐条解析，按类型码分派：
//      · 0x10AB..0x10B2 → 把"候选地址(desc+0x10)"存入 Candidates[类型-0x10AB]
//        （要求候选 > ImageBaseVal 且 候选-ImageBaseVal < ImageSize）；
//      · 0x107C → 令 k=(desc+0x0C-0x38)/4（要求 (desc+0x0C-0x38)<=0x6C 且 4 字节对齐
//        且 k<=0x1B），sel=(desc+0x08>>3)&7；若 Candidates[sel] 非零，则置 Found=1，
//        并把 (Candidates[sel]-ImageBaseVal) 存入 OutTable[k*0x30+4]、
//        (差值+Loaded) 存入 OutTable[k*0x30+8]；
//      · 0xFFFFEE4E / 0xFFFFEE4F → 若 Found==1 则结束。
//   ⑤ 返回 Found。
UCHAR ParseRsdsDebugInfo(PUCHAR ImageBase, ULONG ImageSize, __int64 OutTable)
{
    UCHAR   Desc[0x30];          // rbp-0x61：DecodeUnicodeChar 输出体（0x30 字节）
    ULONG64 Loaded;              // r12 = GtRead(0x8C1)
    ULONG64 Candidates[8];       // rbp-0x29（0x40 字节）
    ULONG64 ImageBaseVal;        // r14 = [nt+0x30]
    ULONG   CurRva;              // ebx
    ULONG   EntryPoint;          // ebx（初值）
    ULONG   i;
    UCHAR   Found;               // r13b

    Loaded = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8C1);      // 0x140039D9B
    Found = 0;
    if (!Loaded)                                             // 0x140039DA7
        return Found;

    {
        PUCHAR Nt = ImageBase + *(LONG *)(ImageBase + 0x3C);  // 0x140039D86
        EntryPoint   = *(ULONG *)(Nt + 0x28);                // 0x140039DB5
        ImageBaseVal = *(__int64 *)(Nt + 0x30);              // 0x140039DB0

        if (EntryPoint >= ImageSize)                         // 0x140039DBE
            return Found;
        if (EntryPoint + 0x1000 >= ImageSize)                // 0x140039DC6
        {
            CurRva = EntryPoint;
            goto L_SECOND;                                   // 0x140039DCE → 0x140039E24
        }

        // ---- 第一轮：定位首个 0x10CE 记录 ----
        {
            PUCHAR p     = ImageBase + EntryPoint;           // rdi，0x140039DD0
            PUCHAR Limit = p + 0x1000;                       // r12，0x140039DD7

            CurRva = EntryPoint;                             // 兜底
            for (i = 0; i < 0x1E; ++i)                       // 0x140039E12
            {
                if ((UCHAR)DecodeUnicodeChar((unsigned __int8 *)p, (ULONG64)Limit,
                                             (_WORD *)Desc) == 0)   // 0x140039DE8
                    break;                                   // 0x140039DEF → 0x140039E1C

                p += *(ULONG *)(Desc + 0x18);                // 0x140039DF1（指令长度）
                if (*(ULONG *)(*(ULONG64 *)(Desc + 0x28)) == 0x10CE)   // 0x140039DFB
                {
                    ULONG r = (ULONG)(ULONG_PTR)p - (ULONG)(ULONG_PTR)ImageBase
                              + *(ULONG *)(Desc + 0x0C);     // 0x140039E03~E08
                    if (r < ImageSize)                       // 0x140039E0B
                    {
                        CurRva = r;                          // 0x140039E1A
                        break;
                    }
                }
            }
        }
    }

L_SECOND:                                                     // 0x140039E24
    if (CurRva >= ImageSize)                                  // 0x140039E24
        return Found;
    if (CurRva + 0x1000 >= ImageSize)                         // 0x140039E2C
        return Found;

    {
        PUCHAR p   = ImageBase + CurRva;                      // rbx，0x140039E3C
        PUCHAR End = p + 0x1000;                              // rdi，0x140039E47

        // 0x140039E4E：memset(Candidates, 0, 0x40)
        // 0x140039E53 `jmp 0x140039F14` 是跳到"循环条件"（条件在底部），
        // 等价于下方标准的 while 结构，此处直接写成 while。
        memset(Candidates, 0, sizeof(Candidates));

        while (p < End)                                       // 0x140039F14
        {
            ULONG Type;

            if ((UCHAR)DecodeUnicodeChar((unsigned __int8 *)p, (ULONG64)End,
                                         (_WORD *)Desc) == 0)  // 0x140039E62
                return Found;                                 // 0x140039E69 → 0x140039F1D

            Type = *(ULONG *)(*(ULONG64 *)(Desc + 0x28));     // 0x140039E6F/73

            if ((ULONG)(Type - 0x10AB) <= 7)                  // 0x140039E75/7B
            {
                // 候选登记（0x140039E80~EA0）
                LONG v = *(LONG *)(Desc + 0x10);              // 0x140039E80
                if (v > 0                                        // 0x140039E84/86
                    && (ULONG64)v > (ULONG64)ImageBaseVal        // 0x140039E8C/8F
                    && (ULONG)((ULONG)v - (ULONG)ImageBaseVal) < ImageSize)  // 0x140039E94/99
                {
                    Candidates[Type - 0x10AB] = (ULONG64)v;   // 0x140039E9B
                }
            }
            else if (Type == 0x107C)                          // 0x140039EA2
            {
                // 0x140039EA9~EFC
                ULONG v = *(ULONG *)(Desc + 0x0C);            // 0x140039EA9
                ULONG k;
                if ((v - 0x38) <= 0x6C                          // 0x140039EAC/EB2
                    && (v & 3) == 0                             // 0x140039EB4/EB9
                    && ((k = (v - 0x38) >> 2) <= 0x1B))         // 0x140039EBD/EC3
                {
                    ULONG sel = (*(UCHAR *)(Desc + 0x08) >> 3) & 7;   // 0x140039EC8~ED0
                    if (Candidates[sel] != 0)                   // 0x140039ED3/ED9
                    {
                        ULONG rva = (ULONG)Candidates[sel] - (ULONG)ImageBaseVal;  // 0x140039EDB/EEA
                        Found = 1;                              // 0x140039EED
                        *(ULONG  *)(OutTable + (ULONG64)k * 0x30 + 4) = rva;        // 0x140039EF0
                        *(ULONG64*)(OutTable + (ULONG64)k * 0x30 + 8) =
                            (ULONG64)rva + Loaded;              // 0x140039EF4/EF7
                    }
                }
            }
            else if ((ULONG)(Type + 0x11B2) <= 1)             // 0x140039EFE/EF03
            {
                // Type ∈ {0xFFFFEE4E, 0xFFFFEE4F}
                if (Found == 1)                                 // 0x140039F08/0C
                    return Found;
            }

            p += *(ULONG *)(Desc + 0x18);                     // 0x140039F0E/F11（指令长度）
        }
    }
    return Found;                                             // 0x140039F1D
}