// ============================================================
// MiniFilterPreDirEnum — 目录枚举前扫描器
// 对应原始驱动 sub_140015A48（1257 字节 / 331 条指令）
// 【新实现 2026-10-19】此前是安全占位（return 0）。逐条对照 0x140015A48 重建。
//
// 入口守卫仅 3 项：GT[0x20]（PE 缓冲）、GT[0x21]（大小）、GT[3]（内核基址）
//   （0x140015AAB..AC0）—— 与 PreClose 不同，本函数**不读** 0x8CC/0x900/0x8CD/0x4459。
// 窗口（0x140015AC6..B4F）：与 PreClose 同款 ".PAGE" 定位：
//   Base=(Raw<PeSize)?Raw:0（sbb/and 0x140015AF9..AFE）；
//   Va=ReturnVa，为 0 时取 PeSize-Base；Len=min(Va, PeSize-Base)（cmova 0x140015B1C）。
//   扫描游标 rsi=PeBase+Base，终点 r15=PeBase+Base+Len。
// 主循环（0x140015B5E..EFB）：rsi+0x30>=End 或 *rsi!=0x48 → 前进一字节；再按 rsi[1] 分派：
//   · rsi[1]==0x8D（0x140015B79）
//       Cand = (u32)(rsi+7) + (*(u32*)(rsi+3) - (u32)PeBase)（0x140015B7F..B8A）
//       Cand==0 或 >=PeSize → 前进（0x140015B8C..B95）
//       A1（0x140015B9B..C1F）dil==0 且 rsi[0xD]==8 && rsi[0xE]==0x48 &&
//          rsi[0xF]==0x8D && rsi[0x18]==0x10：
//            Alt = (u32)(rsi+0x15) + (*(u32*)(rsi+0x11) - (u32)PeBase)
//            Alt>=PeSize → 前进；否则写
//            GT[0x32E]=Cand、GT[0x330]=Alt、GT[0x32F]=Cand+Gt[3]、GT[0x331]=Alt+Gt[3]
//            置 [rsp+0x43]=1（dil）→ 完成闸门（0x140015D31）
//       A2（0x140015C24..C7D）r9b==0 且 rsi[7]==0x48 && rsi[8]==0x89 &&
//          rsi[0xA]==8 && *(u32*)(rsi+0x11)==0xA0：
//            Cand 已保证有效，写 GT[0x332]=Cand、GT[0x333]=Cand+Gt[3]，
//            置 [rsp+0x42]=1（r9b）（0x140015C75..C78）→ 闸门（0x140015D17）
//       A3（0x140015C82..D12）r8b==0 且 rsi[7]==0x41 && rsi[8]==0xF6：
//            以 [rsi+7, PeEnd-rsi-7) 建上下文，最多 0xA 轮；
//            描述符 +0x88==0x800000 && +0x70==0x1000（0x140015CF1..D02）→ 命中：
//              重算 Cand（0x140015D60..D6B），有效则写
//              GT[0x334]=Cand、GT[0x335]=Cand+Gt[3]，置 [rsp+0x41]=1（r8b，0x140015D8E..D97）
//            未命中 → 闸门（0x140015D22）
//   · 否则若 rsi[0]==0x48 && rsi[1]==0x8B（0x140015DB3..DBF）：
//       edi = (u32)(rsi+7) + (*(u32*)(rsi+3) - (u32)PeBase)（0x140015DC5..DCE）
//       edi==0 或 >=PeSize → 前进；dl!=0 → 闸门
//       否则以 [rsi+7, PeEnd-rsi-7) 解码最多 0xA 轮（0x140015E23..E95）：
//         hit34 = (+0x88 的 bit16) && (GT[0x336] + 描述符+0x78) == 0（0x140015E40..E62）
//         hit35 = (+0x88 的 bit16) && 描述符+0x78 == 0xBC0（0x140015E6D..E85）
//         两者同时成立 → 写 GT[0x337]=edi+Gt[3]（0x140015ECE），置 [rsp+0x40]=1（dl）
// 完成闸门（0x140015D22 / D31 / D43 / EB5）：[0x43]==1 && [0x42]==1 && [0x41]==1 &&
//   [0x40]==1 → 收尾返回；否则前进下一字节。四标志跨字节持久。
// 写入槽位：0x32E/0x32F/0x330/0x331、0x332/0x333、0x334/0x335、0x337
// ============================================================
__int64 MiniFilterPreDirEnum(void)
{
    const ULONG64 PeBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* r12  0x140015A7F */
    const ULONG   PeSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);     /* r14d 0x140015A91 */
    const ULONG64 NtBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);      /* r13  0x140015A9E */

    ULONG64 PeEnd = 0;          /* [rsp+0x60] */
    ULONG64 End   = 0;          /* r15 */
    ULONG64 rsi   = 0;          /* 扫描游标 */
    UCHAR   f43 = 0;            /* [rsp+0x43]（dil） */
    UCHAR   f42 = 0;            /* [rsp+0x42]（r9b） */
    UCHAR   f41 = 0;            /* [rsp+0x41]（r8b） */
    UCHAR   f40 = 0;            /* [rsp+0x40]（dl） */
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];

    if (!PeBase || !PeSize || !NtBase) return 0;        /* 0x140015AAB..AC0 */

    PeEnd = PeBase + (ULONG64)PeSize;                   /* 0x140015AC6..ADF */
    {
        char  Name[8];                                  /* [rsp+0x48] ".PAGE" */
        ULONG Raw, Base, Va, Len, Avail;
        *(ULONG *)(Name + 0) = 0x4741502Eu;             /* 0x140015AD7 ".PAG" */
        *(ULONG *)(Name + 4) = 0x45u;                   /* 0x140015AE4 "E"    */
        Raw = (ULONG)FindPESectionByName((__int64)PeBase, PeSize, (__int64)Name);
        Base = (Raw < PeSize) ? Raw : 0u;               /* 0x140015AF1..AFE */
        Va = (ULONG)FindPESectionByNameReturnVa((__int64)PeBase, PeSize, (__int64)Name);
        if (Va == 0) Va = PeSize - Base;                /* 0x140015B0A..B11 */
        Avail = PeSize - Base;                          /* 0x140015B13..B1A */
        Len = (Va > Avail) ? Avail : Va;                /* cmova 0x140015B1C */
        rsi = PeBase + (ULONG64)Base;                   /* 0x140015B16 */
        End = PeBase + (ULONG64)Base + (ULONG64)Len;    /* 0x140015B2F..B4A */
    }
    f43 = 0; f42 = 0; f41 = 0; f40 = 0;                 /* 0x140015B21..B43 */
    if (rsi >= End) return 0;                           /* 0x140015B4F..B52 */

    for (;;)
    {
        ULONG Cand;

        if (rsi + 0x30 >= End) break;                   /* 0x140015B5E..B65 */
        if (*(UCHAR *)rsi != 0x48) break;               /* 0x140015B6B..B6F */

        if (*(UCHAR *)(rsi + 1) == 0x8D)                /* 0x140015B75 */
        {
            Cand = (ULONG)(rsi + 7) + (*(ULONG *)(rsi + 3) - (ULONG)PeBase); /* 0x140015B7F..B8A */
            if (Cand == 0 || Cand >= PeSize) goto LD_ADV;                    /* 0x140015B8C..B95 */

            /* A1（0x140015B9B..C1F） */
            if (f43 == 0 &&
                *(UCHAR *)(rsi + 0xD) == 8 && *(UCHAR *)(rsi + 0xE) == 0x48 &&
                *(UCHAR *)(rsi + 0xF) == 0x8D && *(UCHAR *)(rsi + 0x18) == 0x10)
            {
                ULONG Alt = (ULONG)(rsi + 0x15)
                          + (*(ULONG *)(rsi + 0x11) - (ULONG)PeBase);
                if (Alt >= PeSize) goto LD_ADV;                          /* 0x140015BCF..BD2 */
                GtWrite((GLOBAL_TABLE_INDEX)0x32E, (__int64)Cand);                      /* 0x140015BD8 */
                GtWrite((GLOBAL_TABLE_INDEX)0x330, (__int64)Alt);                       /* 0x140015BE6 */
                GtWrite((GLOBAL_TABLE_INDEX)0x32F, (__int64)((ULONG64)Cand + NtBase));  /* 0x140015BF4 */
                GtWrite((GLOBAL_TABLE_INDEX)0x331, (__int64)((ULONG64)Alt  + NtBase));  /* 0x140015C02 */
                f43 = 1;                                                /* 0x140015C17 mov dil,r8b */
                goto GATE;
            }
            /* A2（0x140015C24..C7D） */
            if (f42 == 0 && *(UCHAR *)(rsi + 7) == 0x48 && *(UCHAR *)(rsi + 8) == 0x89 &&
                *(UCHAR *)(rsi + 0xA) == 8 && *(ULONG *)(rsi + 0x11) == 0xA0)
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand);                      /* 0x140015C55 */
                GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)((ULONG64)Cand + NtBase));  /* 0x140015C65 */
                f42 = 1;                                                    /* 0x140015C75 mov r9b,r8b */
                goto GATE;
            }
            /* A3（0x140015C82..D12） */
            if (f41 == 0 && *(UCHAR *)(rsi + 7) == 0x41 && *(UCHAR *)(rsi + 8) == 0xF6)
            {
                int Hit = 0;
                InitPESectionReadContext((__int64)(rsi + 7), (ULONG)PeEnd - (ULONG)rsi - 7u,
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                for (int k = 0; k < 0xA; ++k)                            /* 0x140015CD4..D10 */
                {
                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                    *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                    if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x800000 &&  /* 0x140015CF1..D02 */
                        *(ULONG   *)((PUCHAR)Entry + 0x70) == 0x1000)
                    { Hit = 1; break; }
                }
                if (Hit)                                                     /* 0x140015D60..D97 */
                {
                    ULONG c = (ULONG)(rsi + 7) + (*(ULONG *)(rsi + 3) - (ULONG)PeBase);
                    if (c != 0 && c < PeSize)
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)c);                      /* 0x140015D74 */
                        GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)((ULONG64)c + NtBase));  /* 0x140015D84 */
                        f41 = 1;                                                 /* 0x140015D94 */
                    }
                }
                goto GATE;
            }
            goto GATE;
        }

        /* 0x140015DB3：rsi[1] != 0x8D */
        if (*(UCHAR *)(rsi + 1) != 0x8B) goto LD_ADV;                    /* 0x140015DBB..DBF */
        {
            ULONG Alt = (ULONG)(rsi + 7) + (*(ULONG *)(rsi + 3) - (ULONG)PeBase); /* 0x140015DC5..DCE */
            if (Alt == 0 || Alt >= PeSize) goto LD_ADV;                  /* 0x140015DD0..DD9 */
            if (f40 == 0)                                               /* 0x140015DDF..DE1 */
            {
                InitPESectionReadContext((__int64)(rsi + 7), (ULONG)PeEnd - (ULONG)rsi - 7u,
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                for (int k = 0; k < 0xA; ++k)                            /* 0x140015E23..E95 */
                {
                    ULONG64 F88;
                    UCHAR Hit34, Hit35;
                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                    *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                    F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);
                    /* hit34：bit16 置位且 (GT[0x336]+描述符+0x78)==0（0x140015E40..E62） */
                    Hit34 = ((F88 & 0x10000) != 0 &&
                             (ULONG)((ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336)
                                     + *(ULONG *)((PUCHAR)Entry + 0x78)) == 0) ? 1u : 0u;
                    /* hit35：bit16 置位且 描述符+0x78==0xBC0（0x140015E6D..E85） */
                    Hit35 = ((F88 & 0x10000) != 0 &&
                             *(ULONG *)((PUCHAR)Entry + 0x78) == 0xBC0) ? 1u : 0u;
                    if (Hit34 == 1 && Hit35 == 1)                            /* 0x140015E8A..E8C */
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x337,                    /* 0x140015ECE */
                                (__int64)((ULONG64)Alt + NtBase));
                        f40 = 1;                                             /* 0x140015EE1..EE4 */
                        break;
                    }
                }
            }
        }
        goto GATE;

GATE:                                                    /* 0x140015D22 / D43 / EB5 */
        if (f43 == 1 && f42 == 1 && f41 == 1 && f40 == 1) return 0;     /* 0x140015D55 → 收尾 */
LD_ADV:                                                  /* 0x140015EF5..EFB */
        rsi += 1;
        if (rsi >= End) return 0;
    }
    return 0;
}