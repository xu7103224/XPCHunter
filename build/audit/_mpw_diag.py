#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断：MiniFilterPostWrite 离线为何不写 0x179/0x1A4。
1) 打印 ORIG/MINE 的 ScanFileForPeSectionInfo 返回值；
2) 用各自的 ReadPESectionEntry 手工重走扫描窗口，列出所有 0x558/0x40000 节区
   及其候选值，看是否命中 GT[0x439F]/GT[0x41C5]。"""
import os, sys, struct, re
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64
from pe_image_layout import image_layout
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX

ORIG = os.path.join(HERE, '..', '..', 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')
MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
NT = os.path.join(HERE, 'ntoskrnl_guest.exe')
MP = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')


def sym(n, default=None):
    for ln in open(MP, encoding='utf-8', errors='ignore'):
        m = re.match(r'\s+0001:[0-9a-f]{8}\s+' + n + r'\s+([0-9a-f]{16})\s+f', ln)
        if m:
            return int(m.group(1), 16)
    return default


def mk(drv, rd, wr, img):
    sim = KernelSim(drv); sim.skip_stack_cookie_check()

    def gr(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(i, 0) & MASK64); s._do_ret(uc)

    def gw(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        v = uc.reg_read(UC_X86_REG_RDX) & MASK64
        s._gt_values[i] = v; uc.reg_write(UC_X86_REG_RAX, v); s._do_ret(uc)

    sim.intercept(rd, gr); sim.intercept(wr, gw)
    d = open(os.path.join(HERE, 'gt_orig_19045.bin'), 'rb').read()
    for i in range(len(d) // 8):
        v = struct.unpack_from('<Q', d, i * 8)[0]
        if v:
            sim.set_gt(i, v)
    b = sim.scratch((len(img) + 0xFFF) & ~0xFFF)
    sim.uc.mem_write(b, img)
    sim.set_gt(0x20, b); sim.set_gt(0x21, len(img))
    return sim


img, sz, disk = image_layout(NT)
for tag, drv, sfr, rpe, ic, rd, wr in (
        ('ORIG-PreCleanup', ORIG, 0x140014EE4, 0x14008A54C, 0x14008A7E4, 0x140029EFC, 0x140029FF4),
        ('MINE', MINE, None, sym('ReadPESectionEntry'),
         sym('InitPESectionReadContext'), sym('GtRead'), sym('GtWrite'))):
    sim = mk(drv, rd, wr, img)
    g20, g21, g3 = sim._gt_values.get(0x20, 0), sim._gt_values.get(0x21, 0), sim._gt_values.get(3, 0)
    print('==', tag, 'base20', hex(g20), 'size21', hex(g21), 'nt3', hex(g3),
          'g177', hex(sim._gt_values.get(0x177, 0)), 'g439F', hex(sim._gt_values.get(0x439F, 0)),
          'g41C5', hex(sim._gt_values.get(0x41C5, 0)))
    if sfr is None:
        print('   (ScanFileForPeSectionInfo 已被 LTCG 内联进 MiniFilterPostWrite，无独立符号)')
        continue
    r = sim.call(sfr, (), count=300000000)
    rv = r[1] if isinstance(r, tuple) else r
    print('   ScanFile ->', hex(rv) if isinstance(rv, int) else rv)
    if not isinstance(rv, int) or (rv & 0xFFFFFFFF) == 0xFFFFFFFF:
        continue
    off = rv & 0xFFFFFFFF
    ctx = sim.scratch(0x1000); entry = sim.scratch(0x1000)
    rr0 = sim.call(ic, (g20 + off, (g21 - off) & 0xFFFFFFFF, 2, 0),
                   stack_words=(0, 0, 0, 0, 0xFFFFFFFF, 0, 0, ctx), count=2000000)
    print('   InitPESectionReadContext ->', rr0)
    for i in range(0x100):
        rr = sim.call(rpe, (ctx, entry), count=20000000)
        rc = rr[1] if isinstance(rr, tuple) else rr
        if rc:
            print('   ReadPESectionEntry 结束于第', i, '轮')
            break
        szf = struct.unpack_from('<I', sim.uc.mem_read(entry + 0xF0, 4))[0]
        rp = struct.unpack_from('<Q', sim.uc.mem_read(ctx + 8, 8))[0]
        rp = (rp + szf) & MASK64
        sim.uc.mem_write(ctx + 8, struct.pack('<Q', rp))
        tp = struct.unpack_from('<Q', sim.uc.mem_read(entry + 0x118, 8))[0]
        ty = struct.unpack_from('<H', sim.uc.mem_read(tp + 6, 2))[0]
        f50 = struct.unpack_from('<Q', sim.uc.mem_read(entry + 0x50, 8))[0]
        f38 = struct.unpack_from('<I', sim.uc.mem_read(entry + 0x38, 4))[0]
        f88 = struct.unpack_from('<Q', sim.uc.mem_read(entry + 0x88, 8))[0]
        f78 = struct.unpack_from('<I', sim.uc.mem_read(entry + 0x78, 4))[0]
        if i < 12:
            print('     #%02x rc=%r type=%04x +50=%016x +38=%08x +88=%016x +78=%08x rp=%016x' % (i, rc, ty, f50, f38, f88, f78, rp))
        if ty == 0x558 or f88 == 0x40000:
            cand = (f38 - (g20 & 0xFFFFFFFF) + (rp & 0xFFFFFFFF)) & 0xFFFFFFFF
            print('   #%02x type=%04x +50=%016x +38=%08x +88=%016x +78=%08x readptr=%016x cand=%08x'
                  % (i, ty, f50, f38, f88, f78, rp, cand))
