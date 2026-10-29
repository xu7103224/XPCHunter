# 把块 2/3 的链表遍历改为带严格校验的安全版本（避免 BSOD）
p = 'XPCHunterDrv/src/services/TailHelpers.c'
s = open(p, encoding='utf-8').read()

# --- 块 2：把 list 分支的 Flink 解引用改为先校验再解引用 ---
old_list2 = """                        /* list mode: first Flink, walk until back to head, cap 0x10000 */
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
                        }"""

new_list2 = """                        /* list mode: first Flink, walk until back to head, cap 0x10000.
                           每一步都先校验"当前节点"与"其 Flink 字段"可读，再解引用；
                           旧版本直接在未校验的 Cur 上取 *(ULONG64*)Cur，遇到坏节点即 AV。 */
                        ULONG64 Head = List2;
                        ULONG   Guard = 0;

                        if (MmIsAddressValid((PVOID)Head) && MmIsAddressValid((PVOID)(Head + 7)))
                        {
                            ULONG64 Cur = *(ULONG64 *)Head;
                            while (Guard < 0x10000)
                            {
                                if (Cur == Head) break;
                                if (Cur <= (ULONG64)MmSystemRangeStart) break;
                                if (!MmIsAddressValid((PVOID)Cur)) break;
                                if (!MmIsAddressValid((PVOID)(Cur + 7))) break;   /* 保证能读 Flink */

                                if (RemainingSize2 < 0x10) break;
                                *(ULONG64 *)(ULONG_PTR)(Base2 + 0x18 + (ULONG64)(*pCnt2) * 0x10) = Cur;
                                {
                                    ULONG64 Val = 0;
                                    if (!IsWin7)
                                    {
                                        ULONG64 Ptr = (Cur & 0xFFFFFFFFFFFFFFF0ULL) + 8;
                                        if (Ptr > (ULONG64)MmSystemRangeStart
                                            && MmIsAddressValid((PVOID)Ptr)
                                            && MmIsAddressValid((PVOID)(Ptr + 7)))
                                            Val = *(_QWORD *)Ptr;
                                    }
                                    *(ULONG64 *)(ULONG_PTR)(Base2 + 0x20 + (ULONG64)(*pCnt2) * 0x10) = Val;
                                }
                                ++(*pCnt2);
                                RemainingSize2 -= 0x10;
                                ++Guard;
                                Cur = *(ULONG64 *)Cur;
                            }
                        }"""
assert old_list2 in s, "block2 list anchor"
s = s.replace(old_list2, new_list2, 1)

# --- 块 2 数组分支同样加保护 ---
old_arr = """                            ULONG64 Elem = *(ULONG64 *)Cur;
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
                            Cur += 8;"""
new_arr = """                            ULONG64 Elem = *(ULONG64 *)Cur;
                            if (Elem)
                            {
                                if (RemainingSize2 < 0x10) break;
                                *(ULONG64 *)(ULONG_PTR)(Base2 + 0x18 + (ULONG64)(*pCnt2) * 0x10) = Elem;
                                {
                                    ULONG64 Val = 0;
                                    if (!IsWin7)
                                    {
                                        ULONG64 Ptr = (Elem & 0xFFFFFFFFFFFFFFF0ULL) + 8;
                                        if (Ptr > (ULONG64)MmSystemRangeStart
                                            && MmIsAddressValid((PVOID)Ptr)
                                            && MmIsAddressValid((PVOID)(Ptr + 7)))
                                            Val = *(_QWORD *)Ptr;
                                    }
                                    *(ULONG64 *)(ULONG_PTR)(Base2 + 0x20 + (ULONG64)(*pCnt2) * 0x10) = Val;
                                }
                                ++(*pCnt2);
                                RemainingSize2 -= 0x10;
                            }
                            Cur += 8;"""
assert old_arr in s, "block2 array anchor"
s = s.replace(old_arr, new_arr, 1)

# --- 块 3 同样加保护 ---
old3 = """                        while (1)
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
                        }"""
new3 = """                        while (Guard3 < 0x1000)
                        {
                            if (!MmIsAddressValid((PVOID)Cur3)) break;
                            if (!MmIsAddressValid((PVOID)(Cur3 + 7))) break;  /* Flink 可读 */

                            Cur3 = *(ULONG64 *)Cur3;
                            if (Cur3 == Head3) break;
                            if (Cur3 <= (ULONG64)MmSystemRangeStart) break;
                            if (!MmIsAddressValid((PVOID)Cur3)) break;
                            if (RemainingSize3 < 0x10) break;

                            *(ULONG64 *)(ULONG_PTR)(Base3 + 0x18 + (ULONG64)(*pCnt3) * 0x10) = Cur3;
                            {
                                ULONG64 Val3 = 0;
                                if (!IsWin7)
                                {
                                    ULONG64 Ptr3 = ((ULONG64)Cur3 & 0xFFFFFFFFFFFFFFF0ULL) + 8;
                                    if (Ptr3 > (ULONG64)MmSystemRangeStart
                                        && MmIsAddressValid((PVOID)Ptr3)
                                        && MmIsAddressValid((PVOID)(Ptr3 + 7)))
                                        Val3 = *(_QWORD *)Ptr3;
                                }
                                *(ULONG64 *)(ULONG_PTR)(Base3 + 0x20 + (ULONG64)(*pCnt3) * 0x10) = Val3;
                            }
                            ++(*pCnt3);
                            RemainingSize3 -= 0x10;
                            ++Guard3;
                        }"""
assert old3 in s, "block3 anchor"
s = s.replace(old3, new3, 1)

open(p, 'w', encoding='utf-8').write(s)
print("ok")