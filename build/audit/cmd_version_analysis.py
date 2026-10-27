#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分析原版每个命令处理器是否含版本相关实现，以及分版本实现家族的覆盖情况。

数据源（均在本仓库内，无需 IDA）：
  build/audit/_orig_funcs_ida.json   函数名 -> 起止地址
  build/audit/_orig_callgraph.json   函数名 -> 被调用函数名
  build/audit/_orig_cmdtable.json    命令表槽位 -> 处理器地址
  原版二进制                         用于定位 mov ecx,0x914 ; call GtRead
"""
import json, re, sys, os
import capstone, pefile

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
GT_READ = 0x140029EFC
BUILD_SLOT = 0x914

FUNCS = json.load(open('build/audit/_orig_funcs_ida.json', encoding='utf-8'))
CG = json.load(open('build/audit/_orig_callgraph.json', encoding='utf-8'))
CMDT = json.load(open('build/audit/_orig_cmdtable.json', encoding='utf-8'))

pe = pefile.PE(ORIG, fast_load=True)
BASE = pe.OPTIONAL_HEADER.ImageBase
SECS = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections]
RAW = open(ORIG, 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def off_of(va):
    rva = va - BASE
    for v, vs, p, rs in SECS:
        if v <= rva < v + max(vs, rs):
            return p + (rva - v)

def reads_build(start, size):
    """函数内是否出现 mov ecx,0x914 ; call GtRead（即读构建号）。"""
    o = off_of(start)
    if o is None:
        return False
    insns = list(md.disasm(RAW[o:o + size], start))
    for i, ins in enumerate(insns):
        if ins.mnemonic == 'mov' and ins.op_str == 'ecx, 0x914':
            for j in range(i + 1, min(i + 4, len(insns))):
                if insns[j].mnemonic == 'call' and insns[j].op_str.lower().endswith(format(GT_READ, 'x')):
                    return True
    return False

if __name__ == '__main__':
    direct = {}
    for f in FUNCS:
        if f.get('segment') != '.text':
            continue
        if reads_build(f['start'], f['size']):
            direct[f['name']] = True
    print('直接读构建号的函数: %d 个' % len(direct))

    # 版本相关函数名家族
    pat = re.compile(r'(Win7|Win8|Win81|Win10|Win11|Win2k|WinXP|Vista|Legacy)')
    family = sorted(n for n in CG if pat.search(n))
    print('分版本命名函数: %d 个' % len(family))

    # 命令槽位 -> 处理器
    slot2addr = {int(k): v for k, v in CMDT.items()}
    addr2name = {f['start']: f['name'] for f in FUNCS}

    def reach(name, limit=6000):
        seen, stack = set(), [name]
        while stack and len(seen) < limit:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            for c in CG.get(n, {}).get('callees', []):
                if c not in seen:
                    stack.append(c)
        return seen

    rows = []
    for slot, addr in sorted(slot2addr.items()):
        name = addr2name.get(addr)
        if not name:
            continue
        reachable = reach(name)
        hit = reachable & set(direct)
        fam = sorted({n for n in reachable if pat.search(n)})
        rows.append((slot + 0x20, name, sorted(hit), fam))

    sens = [r for r in rows if r[2]]
    famrows = [r for r in rows if r[3]]
    print('\n命令总数: %d  含版本敏感路径: %d  含分版本命名实现: %d'
          % (len(rows), len(sens), len(famrows)))

    print('\n=== 含分版本命名实现的命令 ===')
    for cmd, name, hit, fam in famrows:
        print('0x%03X %-46s %s' % (cmd, name, ', '.join(fam[:6])))

    print('\n=== 版本敏感但无分版本命名的命令 ===')
    for cmd, name, hit, fam in sens:
        if not fam:
            print('0x%03X %-46s 经由: %s' % (cmd, name, ', '.join(hit[:4])))

    json.dump({'sens': [(c, n, h, f) for c, n, h, f in sens],
               'family': [(c, n, h, f) for c, n, h, f in famrows]},
              open('build/audit/cmd_version_matrix.json', 'w'), indent=1)
