#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最终对拍：原版（CFG 感知提取）vs 我方源码（编译器求值槽位）。"""
import difflib, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gt_cfg_extract as G

ROOT = '.'
SRC = os.path.join(ROOT, 'XPCHunterDrv/src/DriverEntry.c')
ENUM_H = os.path.join(ROOT, 'XPCHunterDrv/inc/xpc_gt_enum.h')
PROBE_DIR = os.path.join(ROOT, 'build/audit/gtprobe')
CLANG = 'E:/DevTools/LLVM/bin/clang.exe'
FUNCS = ['Win7', 'Win8', 'Win81', 'Win81_Update', 'Win10_10240', 'Win10_14393',
         'Win10_15063', 'Win10_17134', 'Win10_18362', 'Win10_19041', 'Win11']

def func_body(name):
    txt = open(SRC, encoding='utf-8', errors='ignore').read()
    for key in ('__int64 InitEprocessOffsets%s(' % name, '__int64 InitEprocessOffsets%s (' % name):
        i = txt.find(key)
        if i >= 0:
            # 用花括号配对确定函数真正结束位置
            b = txt.find('{', i)
            if b < 0:
                continue
            depth = 0
            k = b
            while k < len(txt):
                c = txt[k]
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return txt[i:k + 1]
                k += 1
            return txt[i:]
    return None

def collect_exprs():
    s = set()
    for n in FUNCS:
        b = func_body(n)
        if b:
            for m in re.finditer(r'GtWrite\(\s*([^,]+?)\s*,', b):
                s.add(m.group(1).strip())
    return sorted(s)

def eval_exprs(exprs):
    os.makedirs(PROBE_DIR, exist_ok=True)
    hdr = open(ENUM_H, encoding='utf-8', errors='ignore').read()
    hdr = '\n'.join(l for l in hdr.split('\n') if not l.strip().startswith('#include'))
    open(os.path.join(PROBE_DIR, 'gt_enum_standalone.h'), 'w', encoding='utf-8').write(hdr)
    lines = ['#include <stdio.h>', '#include "gt_enum_standalone.h"', 'int main(void){']
    for k, e in enumerate(exprs):
        lines.append('  printf("{0} %lld\\n", (long long)({1}));'.format(k, e.replace('"', '')))
    lines.append('  return 0; }')
    open(os.path.join(PROBE_DIR, 'probe.c'), 'w', encoding='utf-8').write('\n'.join(lines))
    import subprocess
    subprocess.run([CLANG, '-w', '-o', 'probe.exe', 'probe.c'], cwd=PROBE_DIR, check=True, capture_output=True)
    exe = os.path.abspath(os.path.join(PROBE_DIR, 'probe.exe'))
    out = subprocess.run([exe], capture_output=True, text=True).stdout
    res = {}
    for ln in out.split('\n'):
        p = ln.split()
        if len(p) == 2:
            res[exprs[int(p[0])]] = int(p[1])
    return res

def our_pairs(name, table):
    b = func_body(name)
    out = []
    for m in re.finditer(r'GtWrite\(\s*([^,]+?)\s*,\s*([^;]+?)\s*\)', b):
        sym, val = m.group(1).strip(), m.group(2).strip()
        slot = table.get(sym)
        try:
            v = int(val, 0)
        except Exception:
            v = None
        out.append((None if slot is None else slot & 0xFFFFFFFF, v))
    return out

def norm(v):
    return None if v is None else (v & 0xFFFFFFFF)

if __name__ == '__main__':
    exprs = collect_exprs()
    table = eval_exprs(exprs)
    print('槽位表达式 %d 个，均已由编译器求值' % len(exprs))
    bad = 0
    for n in FUNCS:
        o = G.extract(G.Bin('samples/PCHunter_2024.09.02/View++_Driver64.sys'), *G.ORIG_ADDR[n], 0x140029FF4, 0x140029EFC)
        m = our_pairs(n, table)
        os_, ms_ = [x for x, y in o], [x for x, y in m]
        sm = difflib.SequenceMatcher(a=os_, b=ms_, autojunk=False)
        matched, valmis, only_o, only_m = 0, [], [], []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                for k in range(i2 - i1):
                    ov, mv = norm(o[i1 + k][1]), norm(m[j1 + k][1])
                    if ov is not None and mv is not None and ov != mv:
                        valmis.append((os_[i1 + k], ov, mv))
                    matched += 1
            elif tag in ('replace', 'delete'):
                only_o.extend([(os_[x], o[x][1]) for x in range(i1, i2)])
                if tag == 'replace':
                    only_m.extend([(ms_[x], m[x][1]) for x in range(j1, j2)])
            elif tag == 'insert':
                only_m.extend([(ms_[x], m[x][1]) for x in range(j1, j2)])
        ok = not valmis and not only_o and not only_m
        print('%-14s orig=%3d mine=%3d 对齐=%3d 值不同=%d 仅原版=%d 仅我方=%d %s'
              % (n, len(o), len(m), matched, len(valmis), len(only_o), len(only_m), 'OK' if ok else '<<<'))
        for s, a, b in valmis[:8]:
            print('      槽 %s: 原版=%s 我方=%s' % (('0x%X' % s) if s is not None else '?', a, b))
        if only_o:
            print('      仅原版: %s' % [(('0x%X' % s) if s is not None else '?', v) for s, v in only_o[:10]])
        if only_m:
            print('      仅我方: %s' % [(('0x%X' % s) if s is not None else '?', v) for s, v in only_m[:10]])
        if not ok:
            bad += 1
    print('\n=== 不一致的表: %d / %d ===' % (bad, len(FUNCS)))
