#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
逐函数差分：把「原始驱动」与「我方重编译驱动」中对应同一原始地址的函数
放进同一个模拟内核里分别执行，比对运行时可观测量。

比对维度（每个函数）：
  - 是否跑到返回 / 停在哪里
  - 执行指令数、覆盖基本块数
  - 调用的内核 API 序列
  - 读写的全局表（GT）索引序列  ← 最能反映语义是否一致
  - 返回值

判定：
  identical       两侧轨迹完全一致
  api_diff        API 调用序列不同
  gt_diff         GT 读写序列不同
  length_suspect  执行长度差异过大（>4x 且 >50 条）
  both_blocked    两侧都在同一类外部依赖上停住（无法判定，不算差异）
  other           其余，需人工看

用法：
  python func_diff.py [--limit N] [--only NAME] [--max-funcs K] [--json out.json]
"""
import argparse
import json
import os
import sys

SKILL = r'E:\Work\Dev\Windows\ai\UnicornForDriver\.dsh\skills\windows-driver-emulation\scripts'
sys.path.insert(0, SKILL)

from wdrvemu import parse_file, DriverEmulator          # noqa: E402
import unicorn                                          # noqa: E402
from unicorn.x86_const import (                         # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_RSP)

# 两侧的 GtRead / GtWrite / __security_check_cookie 地址。
# 原始侧由 IDA 确认（固定）；我方侧从链接 map 读，每次重建都会变。
GT_ADDRS = {}


def load_gt_addrs(orig_path, reb_path):
    import re as _re
    sym = json.load(open('build/audit/_sym_addr.json', encoding='utf-8'))
    GT_ADDRS[orig_path] = {'read': 0x140029EFC, 'write': 0x140029FF4,
                           'cookie': 0x14008C8B0}
    need = {'read': 'GtRead', 'write': 'GtWrite', 'cookie': '__security_check_cookie'}
    got = {}
    for k, n in need.items():
        v = sym.get(n)
        if v is None:
            raise RuntimeError(
                f'符号 {n} 不在 map 中——它可能被 LTCG 内联消除了。'
                f'请确认 GlobalTable.c 的 __declspec(noinline) 仍在。')
        got[k] = int(v, 16)
    GT_ADDRS[reb_path] = got
    return GT_ADDRS


ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
REB = 'build/bin/Release/x64/XPCHunterDrv.sys'

# 这三个是驱动自身的关键基础设施，单独执行没有意义（要由 DriverEntry 初始化）
SKIP_ADDR = {0x140029EFC, 0x140029FF4, 0x140029EEC, 0x14008C8B0}


class Run:
    """在模拟内核里执行一个函数，记录可观测量。

    复用 skill 的 DriverEmulator（它自带内核布局、API 桩、KPCR/线程环境），
    只额外挂一个 code hook 来拦截 GtRead / GtWrite / __security_check_cookie。
    """
    def __init__(self, image):
        self.image = image
        self.base = image.image_base

    def execute(self, va, args, limit, gt_snapshot=None):
        emu = DriverEmulator()
        emu.setup_kernel()
        lr = emu.load_image(self.image)
        uc = emu.uc
        # 模拟器把镜像重定位到 lr.base（真实内核地址），所以任何按 preferred base
        # 写的地址都必须先平移；再按 guest 的 52 位有效地址截断。
        delta = lr.base - self.image.image_base
        M52 = (1 << 52) - 1

        def G(pref_va):
            return (pref_va + delta) & M52

        rec = {'api': [], 'gt_r': [], 'gt_w': [], 'instr': 0,
               'status': '', 'ret': None, 'stop': '', 'stopped_at': None}
        gt = dict(gt_snapshot or {})

        # 驱动自身基础设施。注意：**两侧地址不同**——
        #   原始驱动 GtRead=0x140029EFC；我方重编译后是另一个地址。
        #   若硬编码原始地址，我方侧的拦截全部落空，GT 序列永远是空的，
        #   会产生大量假的 gt_read_diff。故从符号表按名字查。
        gts = GT_ADDRS.get(self.image.path)
        if gts is None:
            raise RuntimeError(f'缺 {self.image.path} 的 GT 符号地址')
        GT_READ = G(gts['read'])
        GT_WRITE = G(gts['write'])
        COOKIE = G(gts['cookie'])

        def _do_ret(u):
            rsp = u.reg_read(UC_X86_REG_RSP)
            tgt = int.from_bytes(u.mem_read(rsp, 8), 'little')
            u.reg_write(UC_X86_REG_RSP, rsp + 8)
            u.reg_write(UC_X86_REG_RIP, tgt)

        def on_code(u, address, size, ud):
            rec['instr'] += 1
            a = address & ((1 << 52) - 1)
            if a == GT_READ:
                idx = u.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
                val = gt.get(idx, 0)
                rec['gt_r'].append((idx, val))
                u.reg_write(UC_X86_REG_RAX, val & 0xFFFFFFFFFFFFFFFF)
                _do_ret(u)
            elif a == GT_WRITE:
                idx = u.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
                val = u.reg_read(UC_X86_REG_RDX)
                rec['gt_w'].append((idx, val))
                gt[idx] = val
                u.reg_write(UC_X86_REG_RAX, val)
                _do_ret(u)
            elif a == COOKIE:
                _do_ret(u)

        uc.hook_add(unicorn.UC_HOOK_CODE, on_code)

        # 让 API 桩被记录：包装 emu 的 _on_stub_enter
        api_names = {}
        ctx = getattr(emu, '_api_context', None) or {}
        for item in (emu._api_registry or {}).items() if isinstance(getattr(emu, '_api_registry', None), dict) else []:
            k, v = item
            name = k if isinstance(k, str) else str(k)
            addr = v if isinstance(v, int) else getattr(v, 'address', None)
            if isinstance(addr, int):
                api_names[addr & ((1 << 52) - 1)] = name

        def on_code_api(u, address, size, ud):
            a = address & ((1 << 52) - 1)
            nm = api_names.get(a)
            if nm:
                rec['api'].append((nm, [u.reg_read(r) for r in
                                        (UC_X86_REG_RCX, UC_X86_REG_RDX,
                                         UC_X86_REG_R8, UC_X86_REG_R9)]))
        uc.hook_add(unicorn.UC_HOOK_CODE, on_code_api)

        # 独立栈
        stack_base = 0xfffffa0000000000
        try:
            emu.memory.map(stack_base, 0x20000, 'diffstack', 'stack',
                           unicorn.UC_PROT_ALL)
        except Exception:
            pass
        rsp = stack_base + 0x10000
        SENT = stack_base + 0x1000
        emu.memory.write(SENT, b'\xf4')
        emu.memory.write(rsp, SENT.to_bytes(8, 'little'))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        for i, arg in enumerate(args[:4]):
            uc.reg_write([UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
                          UC_X86_REG_R9][i], arg & 0xFFFFFFFFFFFFFFFF)

        start = G(va)
        try:
            uc.emu_start(start, SENT & ((1 << 52) - 1), count=limit)
            rec['status'] = 'returned'
            rec['ret'] = uc.reg_read(UC_X86_REG_RAX)
        except Exception as e:
            rec['status'] = 'stopped'
            rec['stop'] = str(e)[:110]
            try:
                rec['stopped_at'] = hex(uc.reg_read(UC_X86_REG_RIP))
            except Exception:
                pass
        return rec


def classify(a, b):
    """判定两侧行为的等价性。

    前提：差分器在**同样不完整的模拟环境**里跑两侧，故"同样卡住"不等于一致；
    但 GT 访问序列是**语义指纹**，不依赖参数是否合法，最能反映是否同源。
    分级：
      identical       指令数接近、GT 访问序列相同、返回值相同
      gt_read_diff    GT 读索引序列不同    <- 强信号
      gt_write_diff   GT 写索引序列不同    <- 强信号
      api_diff        内核 API 调用序列不同
      status_diff     一侧返回、另一侧卡住
      ret_diff        两侧都返回但返回值不同
      length_suspect  指令数差异 >4x 且 >50（可能优化差异，也可能语义差异）
      both_blocked    两侧都极早停住（<5 条），环境不足，无法判定
    """
    if a['status'] == 'stopped' and b['status'] == 'stopped'             and a['instr'] < 5 and b['instr'] < 5:
        return 'both_blocked'
    # GT 序列比对要区分两种原因：
    #   index_mismatch —— 两侧都读到了 GT，但**索引集合不同**：真缺陷。
    #   path_diff      —— 一侧读到、另一侧在该参数下没走到：很可能是
    #                    参数/环境导致的路径差异（假阳性），须人工核对，
    #                    不能直接当缺陷。两者分开计数。
    ra, rb = [i for i, _ in a['gt_r']], [i for i, _ in b['gt_r']]
    wa, wb = [i for i, _ in a['gt_w']], [i for i, _ in b['gt_w']]
    if ra != rb:
        if ra and rb:
            return 'gt_index_mismatch'
        return 'gt_path_diff'
    if wa != wb:
        if wa and wb:
            return 'gt_write_index_mismatch'
        return 'gt_write_path_diff'
    if [n for n, _ in a['api']] != [n for n, _ in b['api']]:
        return 'api_diff'
    if a['status'] != b['status']:
        return 'status_diff'
    if a['status'] == 'returned' and b['status'] == 'returned' and a['ret'] != b['ret']:
        return 'ret_diff'
    ia, ib = a['instr'], b['instr']
    if ia and ib and max(ia, ib) > 4 * min(ia, ib) and max(ia, ib) > 50:
        return 'length_suspect'
    return 'identical'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=60000)
    ap.add_argument('--only', default='')
    ap.add_argument('--max-funcs', type=int, default=0)
    ap.add_argument('--json', default='build/audit/_func_diff.json')
    args = ap.parse_args()

    load_gt_addrs(ORIG, REB)
    amap = json.load(open('build/audit/_addr_map.json', encoding='utf-8'))
    orig_img = parse_file(ORIG)
    reb_img = parse_file(REB)

    # 统一注入一组"看起来合法"的 GT 值，让依赖 GT 的函数能往下走
    GT_SEED = {0x3: 0xFFFFF80000000000, 0x20: 0xFFFFF80011110000,
               0x21: 0x200000, 0x22: 0xFFFFF80011110000, 0x23: 0x200000,
               0x914: 0x4A61, 0x1A1: 0xFFFFF88000100000}

    run_o = Run(orig_img)
    run_r = Run(reb_img)

    items = []
    for a_hex, (name, sym_va, where) in amap.items():
        a = int(a_hex, 16)
        if a in SKIP_ADDR:
            continue
        if args.only and args.only.lower() not in name.lower():
            continue
        items.append((a, name, sym_va, where))
    items.sort(key=lambda x: x[0])
    if args.max_funcs:
        items = items[:args.max_funcs]

    print(f'共 {len(items)} 个可差分函数，逐个在模拟内核中执行…\n')
    results = []
    tally = {}
    for a, name, sym_va, where in items:
        ro = run_o.execute(a, (0, 0, 0, 0), args.limit, GT_SEED)
        rr = run_r.execute(sym_va, (0, 0, 0, 0), args.limit, GT_SEED)
        verdict = classify(ro, rr)
        tally[verdict] = tally.get(verdict, 0) + 1
        results.append({'addr': hex(a), 'name': name, 'sym': hex(sym_va),
                        'where': where, 'verdict': verdict,
                        'orig': {k: v for k, v in ro.items() if k != 'blocks'},
                        'reb': {k: v for k, v in rr.items() if k != 'blocks'}})
        if verdict != 'identical':
            print(f'  {verdict:<15} {hex(a)}  {name[:38]:<38} '
                  f'instr {ro["instr"]:>6}/{rr["instr"]:<6} '
                  f'gt_r {len(ro["gt_r"])}/{len(rr["gt_r"])}')

    print('\n' + '=' * 72)
    print('差分结论汇总：')
    for k, v in sorted(tally.items(), key=lambda x: -x[1]):
        print(f'  {k:<16} {v}')
    json.dump({'tally': tally, 'results': results,
               'skipped_infra': sorted(hex(x) for x in SKIP_ADDR)},
              open(args.json, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'\n明细已写出 {args.json}')


if __name__ == '__main__':
    main()