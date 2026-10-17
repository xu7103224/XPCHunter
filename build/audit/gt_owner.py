#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GT 槽归属分析：对缺失的槽，找出原始驱动中**哪个函数**写了它。

方法：反汇编原始 .text，逐个函数扫描 `mov ecx, <idx>` 紧跟 `call GtWrite` 的模式
（GtWrite 形如 lea rcx,[gt]; mov [rcx+rax*8],rdx，其入口 0x140029FF4）。
输出：缺失槽 -> [(函数VA, 函数名)]  ，用于定位要补的实现。
"""
import json
import re
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
BASE = 0x140000000
GTWRITE = 0x140029FF4
GTREAD = 0x140029EFC


def load_text(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    n = struct.unpack_from('<H', d, pe + 6)[0]
    sec = pe + 24 + struct.unpack_from('<H', d, pe + 20)[0]
    for i in range(n):
        o = sec + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
        if nm == '.text':
            return d[ra:ra + rsz], BASE + va, d
    raise SystemExit('no .text')


def load_funcs():
    """原始函数表：{start: {name,size}}"""
    try:
        raw = json.load(open('build/audit/_orig_funcs_ida.json'))
        if isinstance(raw, dict):
            return {int(k, 16) if isinstance(k, str) else k: v for k, v in raw.items()}
        return {f['start']: f for f in raw}
    except Exception:
        return {}


def main():
    missing = sys.argv[1:]  # 槽号（可含 0x）
    if not missing:
        # 默认取报告里那 91 个缺失槽
        txt = open('build/audit/gt_diff_report.txt', encoding='utf-8').read()
        m = re.search(r'=== 只在原驱动出现的槽.*?===\s*\n(.*?)\n===', txt, re.S)
        missing = re.findall(r'GT\[(0x[0-9A-Fa-f]+)\]', m.group(1)) if m else []
    want = {int(x, 16) for x in missing}
    print(f'待定位槽 {len(want)} 个')

    text, tva, whole = load_text(ORIG)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    funcs = load_funcs()

    # 一次线性扫描：维护"最近一次 mov ecx, imm"与当前函数
    hits = {}          # idx -> list of (func_va, func_name, insn_va)
    cur_fn = None
    last_ecx = None
    fn_starts = sorted(funcs) if funcs else []

    for ins in md.disasm(text, tva):
        if fn_starts and ins.address in funcs:
            cur_fn = ins.address
        elif not fn_starts:
            # 无函数表：用 ret 粗略切分
            if ins.mnemonic == 'ret':
                cur_fn = None
        if ins.mnemonic == 'mov' and ins.op_str.startswith('ecx, '):
            v = ins.op_str.split(', ')[1]
            last_ecx = int(v, 16) if v.startswith('0x') else None
        elif ins.mnemonic == 'call' and ins.op_str == hex(GTWRITE):
            if last_ecx is not None:
                nm = funcs.get(cur_fn, {}).get('name', '?') if funcs else '?'
                hits.setdefault(last_ecx, []).append((cur_fn, nm, ins.address))
        elif ins.mnemonic in ('mov', 'lea') and ins.op_str.startswith('ecx,'):
            last_ecx = None

    print()
    found, notfound = 0, []
    for idx in sorted(want):
        h = hits.get(idx)
        if h:
            found += 1
            locs = ', '.join(f'{nm}@{hex(fv-BASE)}' if fv else f'?@{hex(iv)}' for fv, nm, iv in h[:4])
            print(f'GT[0x{idx:X}] <- {locs}')
        else:
            notfound.append(idx)
    print()
    print(f'已定位 {found} / {len(want)}')
    if notfound:
        print('未定位（可能被间接/循环写入）:')
        print('  ' + ' '.join(f'0x{i:X}' for i in notfound))


if __name__ == '__main__':
    main()