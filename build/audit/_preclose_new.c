__int64 MiniFilterPreClose(void)
{
    /* 寄存器级转写。原码寄存器复用严重，故按「寄存器 = 变量」建模：
         rsi   = PeBase（同时在块 A 内当 0..0xA 的计数器）
         r12d  = PeSize
         rdi   = 块 A/B 的 AltCand；全宽 rdi 另承载 PeEnd
         r13   = 扫描游标（[rsp+0x78] 备份）
         r15   = r13+7（块 B 中被复用为步进 1）
         r14d  = Cand（[rsp+0x44]），块内改写为 Alt 候选与标志字节
         ebx   = Base / Alt2 候选 / 标志
       窄写一律用掩码模拟，以求位级一致。标签名 = 原始地址。 */
    const ULONG64 PeBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* rsi   0x14001530B */
    const ULONG   PeSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);     /* r12d  0x140015315 */
    const ULONG64 NtBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);      /* [rsp+0x50] */
    const ULONG   v8CC   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CC);    /* [rbp-0x80] */
    const ULONG   v900   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x900);    /* [rbp-0x70] */
    const ULONG   v8CD   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CD);    /* [rsp+0x70] */
    const ULONG   v4459  = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4459);   /* [rbp-0x78] */

    ULONG64 PeEnd = 0;          /* [rsp+0x58] = PeBase + PeSize */
    ULONG64 End   = 0;          /* [rsp+0x68] = 扫描终点 */
    ULONG64 r13   = 0;          /* 扫描游标 */
    ULONG64 r15   = 0;          /* r13 + 7，或块 B 的步进 */
    ULONG   r14d  = 0;          /* Cand / Alt / 标志字节 */
    ULONG   edi   = 0;          /* 块 A / 块 B 的 AltCand */
    ULONG   esi   = 0;
    ULONG   ebx   = 0;
    UCHAR   dl = 0, r8b = 0;
    UCHAR   f40 = 0, f41 = 0, f42 = 0;    /* [rsp+0x40]/[41]/[42] */
    ULONG   Cand = 0;           /* [rsp+0x44] */
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];

    if (!PeBase || !PeSize || !NtBase) return 0;    /* 0x14001537E..397 */
    if (!v8CC || !v900 || !v8CD) return 0;          /* 0x140015399..3AD */

    edi   = PeSize;                                 /* 0x1400153B3 mov edi,r12d */
    PeEnd = PeBase + (ULONG64)PeSize;               /* 0x1400153BE add rdi,rsi */
    {
        char  Name[8];                              /* [rsp+0x60] ".PAGE" */
        ULONG Raw, Base, Va, Len, Avail;
        *(ULONG *)(Name + 0) = 0x4741502Eu;         /* 0x1400153C4 ".PAG" */
        *(ULONG *)(Name + 4) = 0x45u;               /* 0x1400153D1 "E"    */
        Raw = (ULONG)FindPESectionByName((__int64)PeBase, PeSize, (__int64)Name);
        Base = (Raw < PeSize) ? Raw : 0u;           /* sbb/and 0x1400153E9..3EE */
        ebx  = Base;                                /* 0x1400153EB */
        Va = (ULONG)FindPESectionByNameReturnVa((__int64)PeBase, PeSize, (__int64)Name);
        if (Va == 0) Va = PeSize - Base;            /* 0x1400153F9..3FE */
        Avail = PeSize - Base;                      /* 0x140015407 */
        Len = (Va > Avail) ? Avail : Va;            /* cmova 0x14001540E */
        r13 = PeBase + (ULONG64)Base;               /* 0x140015403 */
        End = PeBase + (ULONG64)Base + (ULONG64)Len;/* 0x140015422 / 42E */
    }
    f42 = 0; f40 = 0; f41 = 0;                      /* 0x14001541D / 425 / 42A */
    dl = 0; r8b = 0; r14d = 0;                      /* 0x140015416 / 413 / 419 */
    if (r13 >= End) return 0;                       /* 0x140015436..439 */

L_140015445:                                        /* ===== 主循环体（0x140015445） ===== */
    if (r13 + 0x30 >= End) goto L_1400159E3;
    if (*(UCHAR *)r13 != 0x48) goto L_1400159E3;
    if (*(UCHAR *)(r13 + 1) != 0x8D) goto L_1400159E3;
    /* 0x140015468..475：Cand = (u32)(r13+7) + (*(u32*)(r13+3) - (u32)PeBase) */
    Cand = (ULONG)(r13 + 7) + (*(ULONG *)(r13 + 3) - (ULONG)PeBase);
    r14d = Cand;                                    /* 0x140015475 [rsp+0x44] 备份 */
    if (Cand == 0 || Cand >= PeSize) goto L_1400159E3;
    r15 = r13 + 7;
    if (*(UCHAR *)r15 != 0x48) goto L_140015856;    /* 0x14001548D..491 */
    if (*(UCHAR *)(r13 + 8) != 0x89) goto L_140015856;
    if (*(UCHAR *)(r13 + 0xA) != 8)  goto L_140015856;
    if (r8b != 0) goto L_140015584;                 /* 0x1400154AD..4B0 */

    /* ===== 块 A（0x1400154B6..56E）：最多 0xA 轮 ===== */
    edi = 0;                                        /* 0x1400154BA xor edi,edi */
    r14d &= 0xFFFFFF00u;                            /* 0x1400154E4 xor r14b,r14b */
    ebx  &= 0xFFFFFF00u;                            /* 0x1400154E7 xor bl,bl */
    InitPESectionReadContext((__int64)r15, (ULONG)PeEnd - (ULONG)r13 - 7u,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    esi = 0;                                        /* 0x1400154EE xor esi,esi */
    for (;;)
    {
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto L_140015570;
        *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
        {
            USHORT ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
            if (ty == 0x512)                                    /* 0x140015528..551 */
            {
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000 &&
                    *(ULONG   *)((PUCHAR)Entry + 0x78) != 0 &&
                    *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40)
                {
                    ULONG c = *(ULONG *)((PUCHAR)Entry + 0x78) - (ULONG)PeBase
                            + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                    if (c != 0 && c < PeSize && edi == 0) edi = c;
                }
            }
            else if (*(ULONG *)((PUCHAR)Entry + 0x40) == v8CC)  /* 0x14001566D..67E */
            {
                r14d = 1;
                goto L_14001555D;
            }
            else                                                /* 0x140015683..695 */
            {
                UCHAR lo = (UCHAR)ebx;      /* movzx ebx,bl */
                ebx = (*(ULONG *)((PUCHAR)Entry + 0x40) == v900) ? 1u : (ULONG)lo;
                goto L_140015558;
            }
        }
        /* 类型非 0x512 且两分支均未命中时不会到达此处；为对齐原始 0x140015553 */
L_140015553:
        if ((UCHAR)r14d != 1) goto L_140015569;
        if ((UCHAR)ebx  != 1) goto L_140015569;
        if (edi != 0) goto L_14001569A;
        goto L_140015569;
L_140015558:
        if ((UCHAR)r14d != 1) goto L_140015569;
L_14001555D:
        if ((UCHAR)ebx != 1) goto L_140015569;
        if (edi != 0) goto L_14001569A;
L_140015569:
        esi += 1;                                    /* 0x140015569..56E */
        if (esi < 0xA) continue;
        goto L_140015570;
    }

L_140015570:                                        /* 0x140015570..57A */
    r8b  = f42;
    dl   = f41;
    r14d = Cand;                                    /* 0x140015575 mov r14d,[rsp+0x44] */

L_140015584:                                        /* 0x140015584 */
    if (f40 != 0) goto L_1400159B6;                 /* 0x140015584..589 */
    if (r14d == 0 || r14d >= PeSize) goto L_1400159B6;  /* 0x14001558F..59B */

    /* ===== 块 B（0x1400155A1..755）：最多 0x14 轮 ===== */
    r14d = 0;                                       /* 0x1400155A5 xor r14d,r14d */
    ebx  &= 0xFFFFFF00u;                            /* 0x1400155D0 xor bl,bl */
    edi  &= 0xFFFFFF00u;                            /* 0x1400155D2 xor dil,dil */
    InitPESectionReadContext((__int64)r15, (ULONG)PeEnd - (ULONG)r13 - 7u,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    esi = 0;                                        /* 0x1400155DF xor esi,esi */
    r15 = 1;                                        /* 0x1400155E1 lea r15d,[r14+1] */
    for (;;)
    {
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto L_14001575B;
        *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
        {
            USHORT ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
            if (ty == 0x512)                                    /* 0x140015624..668 */
            {
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000 &&
                    *(ULONG   *)((PUCHAR)Entry + 0x78) != 0 &&
                    *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40)
                {
                    ULONG c = *(ULONG *)((PUCHAR)Entry + 0x78) - (ULONG)PeBase
                            + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                    if (c != 0 && c < PeSize && r14d == 0) r14d = c;
                }
            }
            else if (ty == 0x547)                               /* 0x1400156EC..71B */
            {
                if ((*(ULONG64 *)((PUCHAR)Entry + 0x88) & 0x800000) != 0 &&
                    *(ULONG *)((PUCHAR)Entry + 0x70) == 0x1000 &&
                    *(ULONG *)((PUCHAR)Entry + 0x40) == v8CD)
                {
                    ebx = 1;
                    r15 = 1;
                }
            }
            else if ((USHORT)(ty - 0x53C) <= 7)                 /* 0x14001571D..74B */
            {
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x2000000 &&
                    *(ULONG64 *)((PUCHAR)Entry + 0x70) == 0xFFFFF78000000014ull)
                {
                    UCHAR lo = (UCHAR)edi;   /* movzx edi,dil */
                    edi = (r15 == 0) ? (ULONG)lo : (ULONG)r15;   /* cmove edi,r15d */
                }
            }
        }
        esi += (ULONG)r15;                                  /* 0x14001574F */
        if (esi < 0x14) continue;
        break;
    }

L_14001575B:                                        /* 0x14001575B */
    if ((UCHAR)edi != 1) goto L_1400159AD;          /* 0x140015761 cmp dil,1 */
    if (r14d == 0) goto L_1400159AD;                /* 0x14001576F */
    if ((UCHAR)ebx != 0) goto L_1400157EE;          /* 0x140015778 */
    {   /* 回扫 `C7`：rcx 自 (r13-0x30) 递增至 (r13-7)（0x140015781..7E9） */
        PUCHAR rcx = (PUCHAR)r13 - 0x30;
        PUCHAR hi  = (PUCHAR)(r13 - 7);
        if (r13 <= PeBase) goto L_1400159AD;        /* 0x140015785..788 */
        if ((ULONG64)rcx <= PeBase) goto L_1400159AD;/* 0x14001578E..791 */
        for (;;)
        {
            UCHAR dv;
            if (rcx > hi) goto L_1400159AD;         /* 0x14001579B..79E */
            dv = *rcx;
            if (dv == 0xC7 && (ULONG)rcx[2] == v8CD && *(ULONG *)(rcx + 3) == 0x1000)
                break;                              /* 0x1400157AB..7C0 */
            if (rcx <= (PUCHAR)(r13 - 0xA) && dv == 0xC7 &&
                *(ULONG *)(rcx + 2) == v8CD && *(ULONG *)(rcx + 6) == 0x1000)
                break;                              /* 0x1400157C2..7DD */
            rcx += 1;                               /* 0x1400157DF..7E7 */
        }
        ebx = 1;                                    /* 0x1400157E9 */
    }
L_1400157EE:                                        /* 0x1400157EE */
    if ((UCHAR)ebx != 1) goto L_1400159AD;
    GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)Cand);              /* 0x1400157FB */
    GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)((ULONG64)Cand + NtBase));
    GtWrite((GLOBAL_TABLE_INDEX)0x8EC, (__int64)(ULONG64)r14d);
    GtWrite((GLOBAL_TABLE_INDEX)0x8ED, (__int64)((ULONG64)r14d + NtBase));
    r8b  = f42;                                     /* 0x14001583C */
    dl   = 1;                                       /* 0x140015841 */
    r14d = (r14d & 0xFFFFFF00u) | 1u;               /* 0x140015846 mov r14b,dl */
    f40  = 1;                                       /* 0x140015849 */
    dl   = f41;                                     /* 0x14001584D */
    goto L_1400159BB;

L_14001569A:                                        /* ===== 写块 1（0x14001569A..6E7） ===== */
    r14d = Cand;                                    /* 0x14001569A mov r14d,[rsp+0x44] */
    GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand);              /* 0x14001569F */
    GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)((ULONG64)Cand + NtBase));
    GtWrite((GLOBAL_TABLE_INDEX)0x8EE, (__int64)(ULONG64)edi);
    GtWrite((GLOBAL_TABLE_INDEX)0x8EF, (__int64)((ULONG64)edi + NtBase));
    r8b = 1;                                        /* 0x1400156E0 mov r8b,dl */
    f42 = 1;                                        /* 0x1400156E3 */
    dl  = f41;                                      /* 0x1400156E7 */
    goto L_140015584;

L_140015856:                                        /* ===== 备用支路（0x140015856..9A7） ===== */
    if (dl != 0) goto L_1400159B6;                  /* 0x140015856..858 */
    /* 0x14001585E..882：窗口 = edi - (u32)r13 - 7（edi 此处 = PeSize） */
    InitPESectionReadContext((__int64)r15, edi - (ULONG)r13 - 7u,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    ebx &= 0xFFFFFF00u;                             /* 0x140015880 xor bl,bl */
    edi  = 0;                                       /* 0x140015891 xor edi,edi */
    for (;;)
    {
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto L_1400159AD;
        *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
        {
            USHORT ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
            /* 0x1400158C5..8F0：0x4B5 且 [F0]==6 → ebx = (GT[0x336] == +0x70) */
            if (ty == 0x4B5 && *(ULONG *)((PUCHAR)Entry + 0xF0) == 6)
            {
                UCHAR lo = (UCHAR)ebx;
                ebx = ((ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336) ==
                       *(ULONG *)((PUCHAR)Entry + 0x70)) ? 1u : (ULONG)lo;
            }
            if (edi > 4 && (UCHAR)ebx == 0) goto L_1400159AD;   /* 0x1400158F7..8FE */
            if (ty == 0xE5 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000 &&
                (UCHAR)ebx == 1)
                goto L_140015A24;                               /* 0x14001590C..926 */
            if (ty == 0x558 &&                                  /* 0x14001592C..957 */
                (*(ULONG64 *)((PUCHAR)Entry + 0x50) & 0x4000000) != 0 &&
                *(ULONG *)((PUCHAR)Entry + 0x38) != 0)
            {
                if ((UCHAR)ebx == 0) goto L_1400159AD;
                if (v4459 != 0)
                {
                    ULONG a = *(ULONG *)((PUCHAR)Entry + 0x38) - (ULONG)PeBase
                            + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                    if (v4459 == a) goto L_140015A24;
                }
            }
            else if (ty == 0x50E &&                             /* 0x140015959..995 */
                     *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000 &&
                     *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40 &&
                     (UCHAR)ebx == 1)
            {
                ULONG a = *(ULONG *)((PUCHAR)Entry + 0x40) - (ULONG)PeBase
                        + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                if (a != 0 && a < PeSize && (ULONG64)r14d + 8 == (ULONG64)a)
                    goto L_140015A24;
            }
        }
        edi += 1;                                            /* 0x14001599B..9A7 */
        if (edi >= 0xF) goto L_1400159AD;
    }

L_140015A24:                                        /* 尾写（0x140015A24） */
    GtWrite((GLOBAL_TABLE_INDEX)0x337, (__int64)((ULONG64)r14d + NtBase));
    dl  = 1;                                        /* 0x140015A3C mov dl,r8b */
    f41 = 1;                                        /* 0x140015A3F */
    goto L_1400159B1;

L_1400159AD:                                        /* 0x1400159AD */
    dl  = f41;
    r8b = f42;
L_1400159B1:
L_1400159B6:                                        /* 0x1400159B6 */
    r14d = (r14d & 0xFFFFFF00u) | (ULONG)f40;       /* mov r14b,[rsp+0x40] */
L_1400159BB:                                        /* 完成闸门（0x1400159BB） */
    if (r8b == 1 && (UCHAR)r14d == 1 && dl == 1) return 0;
L_1400159CE:                                        /* 前进（0x1400159CE） */
    r13 += 1;
    if (r13 < End) goto L_140015445;
    return 0;
L_1400159E3:
    goto L_1400159CE;
}