# 重新应用块 1 修复（已在 kd 现场验证：count=11、前 216B 与原版完全相同）
p = 'XPCHunterDrv/src/services/TailHelpers.c'
s = open(p, encoding='utf-8').read()

old = """                while ((unsigned __int64)pSsdt1Table < Ssdt1End && MmIsAddressValid(pSsdt1Table))
                {
                    SsdtEntry = *pSsdt1Table;
                    if (*pSsdt1Table)
                    {
                        if (RemainingSize < 0x10)
                            break;
                        *(_QWORD *)&pOutput[4 * pOutput[4] + 6] = SsdtEntry;
                        if (!IsWin7)
                            SsdtEntry = *(_QWORD *)((SsdtEntry & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                        *(_QWORD *)&pOutput[4 * pOutput[4]++ + 8] = SsdtEntry;
                        RemainingSize -= 16;
                        pOutput += 4;
                    }
                    ++pSsdt1Table;
                }"""

new = """                /* [2026-10-27] per original 0x1400413F0..0x140041470:
                   base+0x10 = count, base+0x18+count*0x10 = slot (entry), +8 = depointered.
                   Old code used pOutput[4 * pOutput[4] + 6]: pOutput had already been
                   advanced to +0x18, so pOutput[4] read +0x28 (always 0) instead of the
                   count at +0x10 -> index stuck at 6 and the cursor/RemainingSize were
                   both advanced, writing out of bounds (the AV kd caught at
                   KernelMemoryOperationDispatch+0xb0a). */
                {
                    ULONG64 BlockBase = (ULONG64)(ULONG_PTR)InputBuffer;
                    ULONG  *pCnt1    = (ULONG *)(BlockBase + 0x10);

                    while ((unsigned __int64)pSsdt1Table < Ssdt1End && MmIsAddressValid(pSsdt1Table))
                    {
                        SsdtEntry = *pSsdt1Table;
                        if (SsdtEntry)
                        {
                            if (RemainingSize < 0x10)
                                break;
                            *(ULONG64 *)(ULONG_PTR)(BlockBase + 0x18 + (ULONG64)(*pCnt1) * 0x10) = SsdtEntry;
                            if (!IsWin7)
                                SsdtEntry = *(_QWORD *)((SsdtEntry & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                            *(ULONG64 *)(ULONG_PTR)(BlockBase + 0x20 + (ULONG64)(*pCnt1) * 0x10) = SsdtEntry;
                            ++(*pCnt1);
                            RemainingSize -= 0x10;
                        }
                        ++pSsdt1Table;
                    }
                    pOutput = (int *)(ULONG_PTR)(BlockBase + 0x18 + (ULONG64)(*pCnt1) * 0x10);
                }"""

assert old in s, "block1 anchor not found"
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8').write(s)
print("block1 fix re-applied")