# 回滚块 2/3 到旧写法（保留块 1 的 BlockBase 修复）
p = 'XPCHunterDrv/src/services/TailHelpers.c'
s = open(p, encoding='utf-8').read()

new2_start = s.index("            /* [2026-10-27 per original 0x14004166D] block 2 is NOT the SSDT2 array:")
new2_end = s.index("            if (RemainingSize2 >= 0x28)", new2_start)

old_block2 = """            pOutput2 = pOutput;
            *pOutput = 2;
            pOutput[4] = 0;
            RemainingSize2 = RemainingSize - 24;
            pOutput3 = pOutput + 6;
            pSsdt2Table = pSsdt2TableSaved;
            if (pSsdt2TableSaved && Ssdt2End)
            {
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)   /*0x140041687*/
                    Ssdt2End = (unsigned __int64)(pSsdt2TableSaved + 64);
                while ((unsigned __int64)pSsdt2Table < Ssdt2End && MmIsAddressValid(pSsdt2Table))
                {
                    Ssdt2Entry = *pSsdt2Table;
                    if (*pSsdt2Table)
                    {
                        if (RemainingSize2 < 0x10)
                            break;
                        *(_QWORD *)&pOutput2[4 * pOutput2[4] + 6] = Ssdt2Entry;
                        if (!IsWin7)
                            Ssdt2Entry = *(_QWORD *)((Ssdt2Entry & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                        *(_QWORD *)&pOutput2[4 * pOutput2[4]++ + 8] = Ssdt2Entry;
                        RemainingSize2 -= 16;
                        pOutput3 += 4;
                    }
                    ++pSsdt2Table;
                }
            }
"""
s = s[:new2_start] + old_block2 + s[new2_end:]

new3_start = s.index("                /* [2026-10-27 per original 0x140041830] block 3 walks the GT[0x2BB] list.")
# 找块 3 之后的 "pOutput5 = pOutput;" 作为结束
new3_end = s.index("                pOutput5 = pOutput;", new3_start)
new3_end = s.index("\n", new3_end) + 1

old_block3 = """                pOutput4 = pOutput3;
                *pOutput3 = 3;
                pOutput3[4] = 0;
                RemainingSize3 = RemainingSize2 - 24;
                pOutput5 = pOutput3 + 6;
                pSsdt3Table = pSsdt3TableSaved;
                if (pSsdt3TableSaved && Ssdt3End)
                {
                    SsdtTableOffset = GetSsdtTableOffset((__int64)pSsdt3TableSaved, Ssdt3End);
                    while ((unsigned __int64)pSsdt3Table < SsdtTableOffset && MmIsAddressValid(pSsdt3Table))
                    {
                        Ssdt3Entry = *pSsdt3Table;
                        if (*pSsdt3Table && RemainingSize3 >= 0x10)
                        {
                            *(_QWORD *)&pOutput4[4 * pOutput4[4] + 6] = Ssdt3Entry;
                            if (!IsWin7)
                                Ssdt3Entry = *(_QWORD *)((Ssdt3Entry & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                            *(_QWORD *)&pOutput4[4 * pOutput4[4]++ + 8] = Ssdt3Entry;
                            RemainingSize3 -= 16;
                            pOutput5 += 4;
                        }
                        ++pSsdt3Table;
                    }
                }
"""
s = s[:new3_start] + old_block3 + s[new3_end:]

open(p, 'w', encoding='utf-8').write(s)
print("rolled back block2/3; block1 fix kept:", "BlockBase" in s)