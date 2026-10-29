# 回滚块 3 到旧写法
p = 'XPCHunterDrv/src/services/TailHelpers.c'
lines = open(p, encoding='utf-8').read().split('\n')

# 块 3：从 "/* [2026-10-27 per original 0x140041830]" 行到 "if (RemainingSize3 >= 0x28)" 前
start = None
for i, l in enumerate(lines):
    if 'per original 0x140041830' in l:
        start = i
        break
assert start is not None

end = None
for i in range(start, len(lines)):
    if 'if (RemainingSize3 >= 0x28)' in lines[i]:
        end = i
        break
assert end is not None

old_block3 = [
    '                pOutput4 = pOutput3;',
    '                *pOutput3 = 3;',
    '                pOutput3[4] = 0;',
    '                RemainingSize3 = RemainingSize2 - 24;',
    '                pOutput5 = pOutput3 + 6;',
    '                pSsdt3Table = pSsdt3TableSaved;',
    '                if (pSsdt3TableSaved && Ssdt3End)',
    '                {',
    '                    SsdtTableOffset = GetSsdtTableOffset((__int64)pSsdt3TableSaved, Ssdt3End);',
    '                    while ((unsigned __int64)pSsdt3Table < SsdtTableOffset && MmIsAddressValid(pSsdt3Table))',
    '                    {',
    '                        Ssdt3Entry = *pSsdt3Table;',
    '                        if (*pSsdt3Table && RemainingSize3 >= 0x10)',
    '                        {',
    '                            *(_QWORD *)&pOutput4[4 * pOutput4[4] + 6] = Ssdt3Entry;',
    '                            if (!IsWin7)',
    '                                Ssdt3Entry = *(_QWORD *)((Ssdt3Entry & 0xFFFFFFFFFFFFFFF0uLL) + 8);',
    '                            *(_QWORD *)&pOutput4[4 * pOutput4[4]++ + 8] = Ssdt3Entry;',
    '                            RemainingSize3 -= 16;',
    '                            pOutput5 += 4;',
    '                        }',
    '                        ++pSsdt3Table;',
    '                    }',
    '                }',
    '',
]

lines = lines[:start] + old_block3 + lines[end:]
open(p, 'w', encoding='utf-8').write('\n'.join(lines))
print("block3 reverted; BlockBase kept:", 'BlockBase' in '\n'.join(lines))