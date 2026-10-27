#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CFG 感知的 GtWrite(slot,value) 提取器。

用基本块 + 前向常量传播（多前驱取交集）解决"线性扫描在分支合并处取错槽位"的问题。
"""
import capstone, pefile, re, sys, json

ALIAS = {}
for full, names in {
    'rax': ['rax', 'eax', 'ax', 'al', 'ah'], 'rbx': ['rbx', 'ebx', 'bx', 'bl', 'bh'],
    'rcx': ['rcx', 'ecx', 'cx', 'cl', 'ch'], 'rdx': ['rdx', 'edx', 'dx', 'dl', 'dh'],
    'rsi': ['rsi', 'esi', 'si', 'sil'], 'rdi': ['rdi', 'edi', 'di', 'dil'],
    'rbp': ['rbp', 'ebp', 'bp', 'bpl'], 'rsp': ['rsp', 'esp', 'sp', 'spl'],
}.items():
    for n in names:
        ALIAS[n] = full
for i in range(8, 16):
    for suf in ('', 'd', 'w', 'b'):
        ALIAS['r%d%s' % (i, suf)] = 'r%d' % i
VOLATILE = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

class Bin:
    def __init__(self, path):
        pe = pefile.PE(path, fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
                     for s in pe.sections]
        self.raw = open(path, 'rb').read()

    def off(self, va):
        rva = va - self.base
        for v, vs, p, rs in self.secs:
            if v <= rva < v + max(vs, rs):
                return p + (rva - v)

def imm_of(tok, env):
    tok = tok.strip()
    canon = ALIAS.get(tok)
    if canon is not None:
        return env.get(canon)
    try:
        if tok.lower().startswith('0x'):
            return int(tok, 16)
        if re.fullmatch(r'-?\d+', tok):
            return int(tok)
    except Exception:
        pass
    return None

def apply_insn(ins, env):
    """更新寄存器常量表；返回被写的目标寄存器（用于终止检测）。"""
    m, ops = ins.mnemonic, ins.op_str
    if not ops:
        return
    dst = ops.split(',')[0].strip()
    dreg = ALIAS.get(dst)
    if m == 'mov' and ',' in ops:
        if dreg:
            v = imm_of(ops.split(',', 1)[1], env)
            if v is None:
                env.pop(dreg, None)
            else:
                env[dreg] = v & 0xFFFFFFFF
    elif m == 'lea' and dreg and '[' in ops:
        inner = ops[ops.index('[') + 1:ops.rindex(']')]
        mm = re.fullmatch(r'(\w+)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)', inner)
        if mm and ALIAS.get(mm.group(1)) in env:
            b = env[ALIAS[mm.group(1)]]
            d = int(mm.group(3), 16) if mm.group(3).lower().startswith('0x') else int(mm.group(3))
            env[dreg] = ((b + d) if mm.group(2) == '+' else (b - d)) & 0xFFFFFFFF
        elif re.fullmatch(r'\w+', inner) and ALIAS.get(inner) in env:
            env[dreg] = env[ALIAS[inner]]
        else:
            env.pop(dreg, None)
    elif m in ('add', 'sub') and dreg and ',' in ops:
        v = imm_of(ops.split(',', 1)[1], env)
        if v is not None and dreg in env:
            env[dreg] = ((env[dreg] + v) if m == 'add' else (env[dreg] - v)) & 0xFFFFFFFF
        else:
            env.pop(dreg, None)
    elif m in ('xor', 'or', 'and') and dreg and ',' in ops:
        src = ops.split(',', 1)[1].strip()
        v = imm_of(src, env)
        if m == 'xor' and ALIAS.get(src) == dreg:
            env[dreg] = 0
        elif m == 'or' and v == 0xFFFFFFFF:
            env[dreg] = 0xFFFFFFFF
        elif v is not None and dreg in env:
            env[dreg] = ((env[dreg] | v) if m == 'or' else (env[dreg] & v)) & 0xFFFFFFFF
        else:
            env.pop(dreg, None)
    elif m in ('inc', 'dec') and dreg in env:
        env[dreg] = (env[dreg] + (1 if m == 'inc' else -1)) & 0xFFFFFFFF

def split_blocks(insns):
    """按跳转目标与跳转指令切分基本块。"""
    if not insns:
        return []
    addr2idx = {ins.address: i for i, ins in enumerate(insns)}
    leaders = {0}
    for i, ins in enumerate(insns):
        if ins.mnemonic.startswith('j') or ins.mnemonic in ('ret', 'retn') or ins.mnemonic == 'call':
            if i + 1 < len(insns):
                leaders.add(i + 1)
        if ins.mnemonic.startswith('j') and ins.operands:
            try:
                t = ins.operands[0].imm
                if t in addr2idx:
                    leaders.add(addr2idx[t])
            except Exception:
                pass
    leaders = sorted(leaders)
    blocks = []
    for k, s in enumerate(leaders):
        e = leaders[k + 1] if k + 1 < len(leaders) else len(insns)
        blocks.append((s, e))
    return blocks

def successors(insns, s, e, addr2idx):
    """返回本块的后继块起始索引。"""
    last = insns[e - 1]
    out = []
    if last.mnemonic == 'ret' or last.mnemonic == 'retn':
        return out
    if last.mnemonic == 'jmp' and last.operands:
        try:
            t = last.operands[0].imm
            if t in addr2idx:
                out.append(addr2idx[t])
        except Exception:
            pass
        return out
    if last.mnemonic.startswith('j') and last.operands:
        try:
            t = last.operands[0].imm
            if t in addr2idx:
                out.append(addr2idx[t])
        except Exception:
            pass
    # 条件跳转或顺序执行都跳到下一块
    if e < len(insns):
        out.append(e)
    return out

def extract(binobj, start, size, gt_write, gt_read):
    insns = list(md.disasm(binobj.raw[binobj.off(start):binobj.off(start) + size], start))
    addr2idx = {ins.address: i for i, ins in enumerate(insns)}
    blocks = split_blocks(insns)
    blk_of = {}
    for bi, (s, e) in enumerate(blocks):
        for i in range(s, e):
            blk_of[i] = bi
    # 前向传播
    entry = [None] * len(blocks)
    entry[0] = {}
    work = [0]
    while work:
        bi = work.pop(0)
        s, e = blocks[bi]
        env = dict(entry[bi] or {})
        for i in range(s, e):
            apply_insn(insns[i], env)
            # call 之后清除易失寄存器
            ins = insns[i]
            if ins.mnemonic == 'call':
                for r in VOLATILE:
                    env.pop(r, None)
        for ni in successors(insns, s, e, addr2idx):
            nb = blk_of.get(ni)
            if nb is None:
                continue
            if entry[nb] is None:
                entry[nb] = dict(env)
                work.append(nb)
            else:
                merged = dict(entry[nb])
                for k in list(merged):
                    if env.get(k) != merged[k]:
                        merged.pop(k, None)
                for k, v in env.items():
                    if k not in merged and k in entry[nb] and entry[nb].get(k) == v:
                        merged[k] = v
                if merged != entry[nb]:
                    entry[nb] = merged
                    work.append(nb)
    # 二次遍历：在每块入口环境上取 GtWrite 参数
    out = []
    for bi, (s, e) in enumerate(blocks):
        env = dict(entry[bi] or {})
        for i in range(s, e):
            ins = insns[i]
            if ins.mnemonic in ('call', 'jmp'):
                try:
                    tgt = ins.operands[0].imm
                except Exception:
                    tgt = None
                if tgt == gt_write:
                    out.append((env.get('rcx'), env.get('rdx')))
            apply_insn(ins, env)
            if ins.mnemonic == 'call':
                for r in VOLATILE:
                    env.pop(r, None)
    return out

ORIG_ADDR = {
    'Win7': (0x1400215A4, 0x968), 'Win8': (0x1400278FC, 0x86C),
    'Win81': (0x140026E78, 0xA84), 'Win81_Update': (0x14002656C, 0x90B),
    'Win10_10240': (0x140024DDC, 0xA11), 'Win10_14393': (0x140021F0C, 0x856),
    'Win10_15063': (0x140022764, 0xA78), 'Win10_17134': (0x1400231DC, 0xA4D),
    'Win10_18362': (0x140023C2C, 0x87C), 'Win10_19041': (0x1400244A8, 0x933),
    'Win11': (0x1400257F0, 0xD7A),
}

if __name__ == '__main__':
    b = Bin('samples/PCHunter_2024.09.02/View++_Driver64.sys')
    res = {}
    for n, (va, sz) in ORIG_ADDR.items():
        pairs = extract(b, va, sz, 0x140029FF4, 0x140029EFC)
        res[n] = pairs
        ns = sum(1 for s, v in pairs if s is None)
        print('%-14s 条目=%3d 槽未解析=%d' % (n, len(pairs), ns))
    json.dump(res, open('build/audit/gt_pairs_cfg.json', 'w'), indent=1)
