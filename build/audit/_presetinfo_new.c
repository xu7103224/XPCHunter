// ============================================================
// MiniFilterPreSetInfo — 设置信息前扫描器
// 对应原始驱动 sub_140015F34（1231 字节 / 317 条指令）
// 【新实现 2026-10-19】此前是安全占位（return 0）。逐条对照 0x140015F34 重建。
//
// 入口 5 项守卫（0x140015FB8..FDC）：GT[0x20]、GT[0x21]、GT[3]、GT[0x8CC]、GT[0x8CD]。
//   保存位置：GT[3]→[rsp+0x58]、GT[0x8CC]→[rsp+0x68]、GT[0x8CD]→[rsp+0x60]。
// 窗口（0x140015FE2..6056）：与 PreClose 同款 ".PAGE" 定位：
//   Base=(Raw<PeSize)?Raw:0；Va=ReturnVa，为 0 时取 PeSize-Base；Len=min(Va,PeSize-Base)；
//   PeEnd=PeBase+PeSize 存于 [rsp+0x48]；游标 rbx=PeBase+Base，终点 r13=PeBase+Base+Len。
//   注意 rbx 在块内被复用为「轮次计数器」，故进入每块前把 rbx+1 存入 [rsp+0x70]，
//   块末从该槽恢复（0x14001605F / 0x140016175）。
// 三块的衔接（按原始跳转）：
//   块 1 守卫失败（f42!=0 或 rbx[7..0xA] 非 `48 89 08`）→ 落块 2；块 1 执行但未写 → 下一字节。
//   块 2 守卫失败（f41!=0 或非 `41 F6` 形态）→ 落块 3；块 2 执行完（无论是否命中）→ 闸门。
//   块 3 守卫（f40==0 && rbx[7]==0x48 && rbx[8]==5 && GT[0x336]==*(u32*)(rbx+9)）→ 执行 → 闸门。
// 闸门（0x1400162D3..2F5）：f42==1 && f41==1 && f40==1 → return 0。
// 写入槽位：块 1 → 0x332/0x333；块 2 → 0x334/0x335；块 3 → 0x337
// ============================================================
__int64 MiniFilterPreSetInfo(void)
{
    const ULONG64 PeBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* r12  0x140015F6B */
    const ULONG   PeSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);     /* esi  0x140015F75 */
    const ULONG64 NtBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);      /* [rsp+0x58] 0x140015F8A */
    const ULONG   v8CC   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CC);    /* [rsp+0x68] 0x140015F9C */
    const ULONG   v8CD   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CD);    /* [rsp+0x60] 0x140015FAE */

    ULONG64 PeEnd = 0;          /* [rsp+0x48] = PeBase + PeSize */
    ULONG64 End   = 0;          /* r13 */
    ULONG64 rbx   = 0;          /* 扫描游标 */
    ULONG64 rdi   = 0;          /* rdi：低 32 位兼作窗口长度与「+0xFF8」标志 */
    UCHAR   f40 = 0;            /* [rsp+0x40] */
    UCHAR   f41 = 0;            /* [rsp+0x41] */
    UCHAR   f42 = 0;            /* [rsp+0x42] */
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];

    if (!PeBase || !PeSize || !NtBase || !v8CC || !v8CD) return 0;  /* 0x140015FB8..FDC */

    rdi   = (ULONG64)PeSize;                            /* 0x140015FE2 mov edi,esi */
    PeEnd = PeBase + (ULONG64)PeSize;                   /* 0x140015FEB add rdi,r12 */
    rdi   = PeEnd;                                      /* rdi 全宽 = PeEnd */
    {
        char  Name[8];                                  /* [rsp+0x50] ".PAGE" */
        ULONG Raw, Base, Va, Len, Avail;
        *(ULONG *)(Name + 0) = 0x4741502Eu;             /* 0x140015FF1 ".PAG" */
        *(ULONG *)(Name + 4) = 0x45u;                   /* 0x140015FFE "E"    */
        Raw = (ULONG)FindPESectionByName((__int64)PeBase, PeSize, (__int64)Name);
        Base = (Raw < PeSize) ? Raw : 0u;               /* 0x14001600B..19 */
        Va = (ULONG)FindPESectionByNameReturnVa((__int64)PeBase, PeSize, (__int64)Name);
        if (Va == 0) Va = PeSize - Base;                /* 0x140016022..28 */
        Avail = PeSize - Base;                          /* 0x14001602A..31 */
        Len = (Va > Avail) ? Avail : Va;                /* cmova 0x140016033..35 */
        End = PeBase + (ULONG64)Base + (ULONG64)Len;    /* 0x140016040..50 */
        rbx = PeBase + (ULONG64)Base;                   /* 0x140016053 */
    }
    f42 = 0; f41 = 0; f40 = 0;                          /* 0x14001602C / 43 / 4B */
    if (rbx >= End) return 0;                           /* 0x14001617F..182 */

    for (;;)                                            /* 循环条件 0x14001617F */
    {
        ULONG Cand;                                     /* r15d */

        if (rbx + 1 + 0x2F >= End) goto LD_NEXT;        /* 0x140016064..6B */
        if (*(UCHAR *)rbx != 0x48) goto LD_NEXT;        /* 0x140016071..74 */
        if (*(UCHAR *)(rbx + 1) != 0x8D) goto LD_NEXT;  /* 0x14001607A..7D */
        Cand = 7u + *(ULONG *)(rbx + 3) + (ULONG)rbx - (ULONG)PeBase;   /* 0x140016083..93 */
        if (Cand == 0 || Cand >= PeSize) goto LD_NEXT;  /* 0x140016096..9F */

        /* ===== 块 1（0x1400160A5..169）：`48 89 08` 双标志 ===== */
        if (f42 == 0 && *(UCHAR *)(rbx + 7) == 0x48 &&
            *(UCHAR *)(rbx + 8) == 0x89 && *(UCHAR *)(rbx + 0xA) == 8)
        {
            int   flagA = 0;                            /* r14b：desc+0x40 == GT[0x8CC] */
            int   wrote = 0;
            ULONG counter = 0;                          /* ebx（rbx 已备份到 [rsp+0x70]） */
            rdi = rdi & ~(ULONG64)0xFF;                 /* 0x140016110 xor dil,dil */
            InitPESectionReadContext((__int64)(rbx + 7), (ULONG)PeEnd - (ULONG)rbx - 7u,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);
            while (counter < 6)                         /* 0x14001611A..169 */
            {
                if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto LD_NEXT;
                *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                if (*(ULONG *)((PUCHAR)Entry + 0x40) == v8CC)      /* 0x14001613B..148 */
                {
                    flagA = 1;
                }
                else
                {
                    rdi = rdi & 0xFFu;                             /* 0x140016151 movzx edi,dil */
                    if (*(ULONG *)((PUCHAR)Entry + 0x40) == 0xFF8)
                        rdi = 1;                                   /* 0x140016155 cmove edi,1 */
                    if (flagA != 1) goto LD_CB;                    /* 0x140016159..15C */
                }
                if ((UCHAR)rdi == 1)                               /* 0x14001615E..161 */
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand);                     /* 0x1400161BB */
                    GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)((ULONG64)Cand + NtBase)); /* 0x1400161CD */
                    f42 = 1;                                       /* 0x1400161E5 */
                    wrote = 1;
                    break;
                }
LD_CB:
                counter += 1;                                  /* 0x140016163..166 */
            }
            if (!wrote) goto LD_NEXT;                          /* 0x14001616B */
            goto LD_GATE;                                      /* 0x1400161EA */
        }

        /* ===== 块 2（0x1400161EF..2CE）：`41 F6` 双形态 ===== */
        if (f41 == 0 &&
            ((*(UCHAR *)(rbx + 7) == 0x41 && *(UCHAR *)(rbx + 8) == 0xF6) ||
             (*(UCHAR *)(rbx + 0xA) == 0x41 && *(UCHAR *)(rbx + 0xB) == 0xF6)))
        {
            int hit = 0;
            /* 窗口长度取 edi（0x14001621B..243）；edi 可能已被块 1 改为 0/1 */
            InitPESectionReadContext((__int64)(rbx + 7), (ULONG)rdi - (ULONG)rbx - 7u,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);
            for (int k = 0; k < 0xA; ++k)                       /* 0x14001624E..28C */
            {
                if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x800000 &&   /* 0x140016269..284 */
                    *(ULONG   *)((PUCHAR)Entry + 0x70) == 0x1000 &&
                    *(ULONG   *)((PUCHAR)Entry + 0x40) == v8CD)
                { hit = 1; break; }
            }
            if (!hit)                                           /* 回扫 `C7` 0x14001628E..2C7 */
            {
                PUCHAR rcx = (PUCHAR)rbx - 0x30;
                PUCHAR hi  = (PUCHAR)(rbx - 7);
                if (rbx > PeBase && (ULONG64)rcx > PeBase && rcx < hi)
                {
                    for (;;)
                    {
                        if (rcx >= hi) break;                   /* 0x1400162C4..2C7 */
                        if (rcx[0] == 0xC7 && (ULONG)rcx[2] == (v8CD & 0xFF) &&
                            *(ULONG *)(rcx + 3) == 0x1000)
                        { hit = 1; break; }                     /* 0x1400162AA..2BF */
                        rcx += 1;
                    }
                }
            }
            if (hit)                                            /* 0x140016300..32C */
            {
                ULONG c = *(ULONG *)(rbx + 3) + 7u + (ULONG)rbx - (ULONG)PeBase;
                if (c != 0 && c < PeSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)c);                     /* 0x140016315 */
                    GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)((ULONG64)c + NtBase)); /* 0x140016324 */
                    f41 = 1;                                                            /* 0x140016334 */
                }
            }
            goto LD_GATE;                                       /* 0x140016339 → 0x1400162CE */
        }

        /* ===== 块 3（0x14001633B..3FE）：`48 05` + GT[0x336] 比对 ===== */
        if (f40 == 0 && *(UCHAR *)(rbx + 7) == 0x48 && *(UCHAR *)(rbx + 8) == 5 &&
            (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336) == *(ULONG *)(rbx + 9))   /* 0x14001633B..359 */
        {
            InitPESectionReadContext((__int64)(rbx + 7), (ULONG)PeEnd - (ULONG)rbx - 7u,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);
            for (int k = 0; k < 0xF; ++k)                       /* 0x140016394..3D6 */
            {
                USHORT ty;
                if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
                if (ty == 0xE5 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000)   /* 0x1400163BB..3C9 */
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x337,                         /* 0x1400163DB..3E5 */
                            (__int64)((ULONG64)Cand + NtBase));
                    f40 = 1;                                               /* 0x1400163ED */
                    break;
                }
            }
        }

LD_GATE:                                                        /* 0x1400162D3..2F5 */
        if (f42 == 1 && f41 == 1 && f40 == 1) return 0;         /* 0x1400162F2..2F5 */
LD_NEXT:                                                        /* 0x140016175..182 */
        rbx += 1;
        if (rbx >= End) return 0;
    }
    return 0;
}