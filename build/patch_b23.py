# 0x047 块 2/3 改为原版链表语义
p = 'XPCHunterDrv/src/services/TailHelpers.c'
s = open(p, encoding='utf-8').read()

old = """            pOutput2 = pOutput;
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
            }"""

new = """            /* [2026-10-27 per original 0x14004166D] block 2 is NOT the SSDT2 array:
               it walks the list at GT[0x2B8] (lazy-init via CmdEnumFileSystemCallback),
               length slot GT[0x2BA]. build==0xA28/0xECE uses the array branch
               (0x140041789); everything else (incl. 18362) uses the list branch.
               Addressing matches block 1: base+0x10 = count, base+0x18+count*0x10 = slot. */
            {
                ULONG64 Base2   = (ULONG64)(ULONG_PTR)pOutput;
                ULONG  *pCnt2   = (ULONG *)(Base2 + 0x10);
                ULONG64 List2   = (ULONG64)GtRead(GtKernelDataField38);   /* GT[0x2B8] */
                ULONG64 Size2   = (ULONG64)GtRead(GtKernelDataField40);   /* GT[0x2BA] */

                *pOutput = 2;
                *pCnt2   = 0;
                RemainingSize2 = RemainingSize - 24;

                if (!List2)
                {
                    CmdEnumFileSystemCallback();
                    List2 = (ULONG64)GtRead(GtKernelDataField38);
                }

                if (List2 && Size2)
                {
                    ULONG Build2 = (ULONG)GtRead(GtWindowsBuildNumber);
                    if (Build2 == 0xA28 || Build2 == 0xECE)
                    {
                        /* array mode (0x140041789): stride 8 over GT[0x2B9] entries */
                        ULONG64 Cur  = List2;
                        ULONG64 End  = List2 + (ULONG)GtRead(GtKernelDataField39);
                        while (Cur < End && MmIsAddressValid((PVOID)Cur))
                        {
                            ULONG64 Elem = *(ULONG64 *)Cur;
                            if (Elem)
                            {
                                if (RemainingSize2 < 0x10) break;
                                *(ULONG64 *)(ULONG_PTR)(Base2 + 0x18 + (ULONG64)(*pCnt2) * 0x10) = Elem;
                                if (!IsWin7)
                                    *(ULONG64 *)(ULONG_PTR)(Base2 + 0x20 + (ULONG64)(*pCnt2) * 0x10)
                                        = *(_QWORD *)((Elem & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                                else
                                    *(ULONG64 *)(ULONG_PTR)(Base2 + 0x20 + (ULONG64)(*pCnt2) * 0x10) = 0;
                                ++(*pCnt2);
                                RemainingSize2 -= 0x10;
                            }
                            Cur += 8;
                        }
                    }
                    else
                    {
                        /* list mode: first Flink, walk until back to head, cap 0x10000 */
                        ULONG64 Head = List2;
                        ULONG   Guard = 0;

                        if (MmIsAddressValid((PVOID)Head))
                        {
                            ULONG64 Cur = *(ULONG64 *)Head;
                            while (Cur != Head
                                && Cur > (ULONG64)MmSystemRangeStart
                                && MmIsAddressValid((PVOID)Cur)
                                && Guard < 0x10000)
                            {
                                if (RemainingSize2 < 0x10) break;
                                *(ULONG64 *)(ULONG_PTR)(Base2 + 0x18 + (ULONG64)(*pCnt2) * 0x10) = Cur;
                                if (!IsWin7)
                                    *(ULONG64 *)(ULONG_PTR)(Base2 + 0x20 + (ULONG64)(*pCnt2) * 0x10)
                                        = *(_QWORD *)(((ULONG64)Cur & 0xFFFFFFFFFFFFFFF0ULL) + 8);
                                else
                                    *(ULONG64 *)(ULONG_PTR)(Base2 + 0x20 + (ULONG64)(*pCnt2) * 0x10) = 0;
                                ++(*pCnt2);
                                RemainingSize2 -= 0x10;
                                ++Guard;
                                Cur = *(ULONG64 *)Cur;
                            }
                        }
                    }
                }
                pOutput = (int *)(ULONG_PTR)(Base2 + 0x18 + (ULONG64)(*pCnt2) * 0x10);
            }"""

assert old in s, "block2 anchor not found"
s = s.replace(old, new, 1)

old3 = """                pOutput4 = pOutput3;
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
                }"""

new3 = """                /* [2026-10-27 per original 0x140041830] block 3 walks the GT[0x2BB] list.
                   Start is r15 = head then r15 = [r15] inside the loop (one step later
                   than block 2), stop at head, cap 0x1000. */
                {
                    ULONG64 Base3 = (ULONG64)(ULONG_PTR)pOutput3;
                    ULONG  *pCnt3 = (ULONG *)(Base3 + 0x10);
                    ULONG64 Head3 = (ULONG64)GtRead(GtKernelDataField41);   /* GT[0x2BB] */

                    *pOutput3 = 3;
                    *pCnt3    = 0;
                    RemainingSize3 = RemainingSize2 - 24;

                    if (Head3 && MmIsAddressValid((PVOID)Head3))
                    {
                        ULONG64 Cur3 = Head3;
                        ULONG   Guard3 = 0;

                        while (1)
                        {
                            Cur3 = *(ULONG64 *)Cur3;
                            if (Cur3 == Head3) break;
                            if (Cur3 <= (ULONG64)MmSystemRangeStart) break;
                            if (!MmIsAddressValid((PVOID)Cur3)) break;
                            if (Guard3 >= 0x1000) break;
                            if (RemainingSize3 < 0x10) break;

                            *(ULONG64 *)(ULONG_PTR)(Base3 + 0x18 + (ULONG64)(*pCnt3) * 0x10) = Cur3;
                            if (!IsWin7)
                                *(ULONG64 *)(ULONG_PTR)(Base3 + 0x20 + (ULONG64)(*pCnt3) * 0x10)
                                    = *(_QWORD *)(((ULONG64)Cur3 & 0xFFFFFFFFFFFFFFF0ULL) + 8);
                            else
                                *(ULONG64 *)(ULONG_PTR)(Base3 + 0x20 + (ULONG64)(*pCnt3) * 0x10) = 0;
                            ++(*pCnt3);
                            RemainingSize3 -= 0x10;
                            ++Guard3;
                        }
                    }
                    pOutput = (int *)(ULONG_PTR)(Base3 + 0x18 + (ULONG64)(*pCnt3) * 0x10);
                }"""

assert old3 in s, "block3 anchor not found"
s = s.replace(old3, new3, 1)

open(p, 'w', encoding='utf-8').write(s)
print("ok")