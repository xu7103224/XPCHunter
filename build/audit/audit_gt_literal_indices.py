#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计源码里 `GtRead/GtWrite` 的字面量索引是否存在于对应原始函数中。

关键点：原始侧必须**从函数入口开始**线性解码（否则会从指令中间起解、
落到非法指令上导致漏检）。上一版从 call-24 字节起解，误报率极高。

用法: python audit_gt_literal_indices.py [--verbose]
"""
import os, re, sys, glob, struct, json
import capstone

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
HERE = os.path.join(ROOT, 'build', 'audit')
ORIG = os.path.join(ROOT, 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
IB = 0x140000000
VERBOSE = '--verbose' in sys.argv

d = open(ORIG, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
opt = struct.unpack_from('<H', d, pe + 20)[0]
sec = pe + 24 + opt
secs = []
for i in range(nsec):
    o = sec + i * 40
    nm = d[o:o + 8].rstrip(b'\x00').decode('latin1')
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, o + 8)
    secs.append((nm, va, vsz, ra, rsz))


def va2off(va):
    for nm, sva, vsz, ra, rsz in secs:
        if sva <= va - IB < sva + rsz:
            return ra + (va - IB - sva)
    return None


funcs = json.load(open(os.path.join(HERE, '_orig_funcs_ida.json'), encoding='utf-8'))
GTREAD, GTWRITE = 0x140029EFC, 0x140029FF4
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# ---------- 从每个函数入口解码，收集 GT 索引 ----------
orig_idx = {}
for f in funcs:
    s, e, name = f['start'], f['end'], f['name']
    off = va2off(s)
    if off is None:
        continue
    size = min(e - s, 0x2000)
    code = d[off:off + size]
    last_ecx = None
    idx = set()
    for ins in md.disasm(code, s):
        if ins.mnemonic == 'mov' and ins.op_str.startswith('ecx,'):
            try:
                last_ecx = int(ins.op_str.split(',')[1].strip(), 0)
            except ValueError:
                last_ecx = None
        elif ins.mnemonic == 'lea' and ins.op_str.startswith('ecx,'):
            last_ecx = None          # 动态索引
        elif ins.mnemonic in ('xor', 'and', 'or', 'add', 'sub') and ins.op_str.startswith('ecx,'):
            last_ecx = None
        elif ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
            try:
                t = int(ins.op_str, 16)
            except ValueError:
                t = 0
            if t in (GTREAD, GTWRITE) and last_ecx is not None:
                idx.add(last_ecx)
            if t in (GTREAD, GTWRITE):
                pass
    if idx:
        orig_idx[name] = idx

# ---------- 源码侧 ----------
SRC = sorted(glob.glob(os.path.join(ROOT, 'XPCHunterDrv', 'src', '**', '*.c'), recursive=True))
pat_cite = re.compile(r'0x(1400[0-9A-Fa-f]{5})')
pat_idx = re.compile(r'Gt(?:Read|Write)\s*\(\s*(?:\(GLOBAL_TABLE_INDEX\)|\(enum _GLOBAL_TABLE_INDEX\))?\s*'
                     r'(?:0x([0-9A-Fa-f]+)|(\d+))\s*\)')
BAD = {'GT', 'Handler', 'Table', 'Win10', 'RS3', 'Result', 'Entry', 'Index', 'if', 'for', 'while', 'switch'}
fnmap = {f['start']: f['name'] for f in funcs}
bounds = sorted((f['start'], f['end'], f['name']) for f in funcs)


def func_of(va):
    for s, e, n in bounds:
        if s <= va < e:
            return n
    return None


problems = []
checked = 0
for path in SRC:
    text = open(path, encoding='utf-8', errors='ignore').read()
    lines = text.split('\n')
    for li, line in enumerate(lines):
        code = line.split('//')[0].rstrip()
        if not code or code[:1] in (' ', '\t', '#'):
            continue
        m = re.match(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(', code)
        if not m or code.endswith(';'):
            continue
        name = m.group(1)
        if name in BAD:
            continue
        depth = 0
        j = li
        started = False
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            if '{' in lines[j]:
                started = True
            if started and depth == 0:
                break
            j += 1
        if not started or depth != 0:
            continue
        body = '\n'.join(lines[li:j + 1])
        head = '\n'.join(lines[max(0, li - 10):li])
        cites = pat_cite.findall(head)
        if not cites:
            continue
        ofn = func_of(int(cites[-1], 16))
        if not ofn or ofn not in orig_idx:
            continue
        used = set()
        for a, b in pat_idx.findall(body):
            used.add(int(a, 16) if a else int(b))
        if not used:
            continue
        checked += 1
        extra = used - orig_idx[ofn]
        if extra:
            problems.append((os.path.relpath(path, ROOT), li + 1, name, ofn,
                             sorted(extra), sorted(orig_idx[ofn])))

print('原始侧：%d 个函数含立即数 GT 索引' % len(orig_idx))
print('源码侧：%d 个函数可比对' % checked)
print('可疑：%d' % len(problems))
print()
for p, ln, name, ofn, extra, orig in problems:
    print('%s:%d  %s  (原始 %s)' % (p, ln, name, ofn))
    print('   多出: %s' % [hex(x) for x in extra])
    if VERBOSE:
        print('   原始: %s' % [hex(x) for x in orig])