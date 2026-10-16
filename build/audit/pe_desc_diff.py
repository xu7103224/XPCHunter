# -*- coding: utf-8 -*-
"""
描述符流差分：把**同一段真实 PE 字节**分别喂给原始驱动与我方驱动的
ReadPESectionEntry，逐次调用、逐字段比对产出的 0x120 字节指令描述符。

用途：定位「我方解码链不产出调用方所读载荷字段（+0x38/+0x50/+0x78/+0x88）」
这一整类缺陷 —— 所有节区扫描函数都依赖这些字段做匹配。

判据：两侧的描述符字段序列一致 = 解码链等价。
"""
import json
import sys

sys.path.insert(0, r'E:\Work\Dev\Windows\ai\UnicornForDriver\.dsh\skills\windows-driver-emulation\scripts')
from wdrvemu import parse_file, DriverEmulator   # noqa: E402
import unicorn                                   # noqa: E402
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_RIP, UC_X86_REG_RSP)

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
REB = 'build/bin/Release/x64/XPCHunterDrv.sys'
INP = 'build/audit/_pe_input.bin'
SYM = json.load(open('build/audit/_sym_addr.json', encoding='utf-8'))

SIDES = {
    # region = 解码表区起点（原始 0x140096A30；本方 g_PeDecodeTableRegion）
    ORIG: {'read': 0x14008A54C, 'table': 0x140097E50, 'cookie': 0x14008C8B0,
           'region': 0x140096A30},
    REB: {'read': int(SYM['ReadPESectionEntry'], 16),
          'table': int(SYM['g_PeDecodeTableRegion'], 16) + 0x1420,  # 表区镜像 + 0x1420 = 原 0x97E50
          'cookie': int(SYM['__security_check_cookie'], 16),
          'region': int(SYM['g_PeDecodeTableRegion'], 16)},
}
M52 = (1 << 52) - 1

# 描述符字段（偏移按原始布局）：(名, 偏移, 字节数)
FIELDS = [('md', 0x00, 4), ('mdup', 0x04, 4), ('adsz', 0x08, 4),
          ('flags', 0x20, 4), ('opsz', 0x24, 4), ('subtype', 0x28, 2),
          ('type5', 0x2C, 4), ('F38', 0x38, 4), ('F50', 0x50, 8),
          ('F78', 0x78, 4), ('F88', 0x88, 8), ('E4', 0xE4, 1),
          ('E8', 0xE8, 8), ('cons', 0xF0, 4), ('dp', 0x118, 8)]


def run_side(path, n=16):
    img = parse_file(path)
    emu = DriverEmulator()
    emu.setup_kernel()
    lr = emu.load_image(img)
    uc = emu.uc
    delta = lr.base - img.image_base
    G = lambda x: (x + delta) & M52

    BUF = 0xfffffa0020000000
    CTX = 0xfffffa0020008000
    DESC = 0xfffffa0020009000
    SB = 0xfffffa0000000000
    data = open(INP, 'rb').read()
    emu.memory.map(BUF, 0x4000, 'pe_input', 'data', unicorn.UC_PROT_ALL)
    emu.memory.write(BUF, data)
    emu.memory.map(CTX, 0x1000, 'ctx', 'data', unicorn.UC_PROT_ALL)
    emu.memory.map(DESC, 0x1000, 'desc', 'data', unicorn.UC_PROT_ALL)
    try:
        emu.memory.map(SB, 0x20000, 'stack', 'stack', unicorn.UC_PROT_ALL)
    except Exception:
        pass
    rsp = SB + 0x10000
    SENT = SB + 0x1000
    emu.memory.write(SENT, b'\xf4')

    def wr64(a, v):
        emu.memory.write(a, (v & M52).to_bytes(8, 'little'))

    # 上下文（0x48）：解码表 / 读指针 / 结束指针 / Mode=2 / ModeDup=2 / AddrSize=1
    wr64(CTX + 0x00, G(SIDES[path]['table']))
    wr64(CTX + 0x08, BUF)
    wr64(CTX + 0x10, BUF + len(data))
    emu.memory.write(CTX + 0x18, (2).to_bytes(4, 'little'))
    emu.memory.write(CTX + 0x1C, (2).to_bytes(4, 'little'))
    emu.memory.write(CTX + 0x20, (1).to_bytes(4, 'little'))
    wr64(CTX + 0x28, 0)
    wr64(CTX + 0x30, 0)
    wr64(CTX + 0x38, 0)
    emu.memory.write(CTX + 0x40, (0xFFFFFFFF).to_bytes(4, 'little'))

    # __security_check_cookie 直接返回（两侧各自的地址）
    def on_code(u, address, size, ud):
        if (address & M52) == G(SIDES[path]['cookie']):
            r = u.reg_read(UC_X86_REG_RSP) & M52      # 【修正】模拟器映射在 52 位掩码地址上
            tgt = int.from_bytes(u.mem_read(r, 8), 'little')
            u.reg_write(UC_X86_REG_RSP, r + 8)
            u.reg_write(UC_X86_REG_RIP, tgt)
    uc.hook_add(unicorn.UC_HOOK_CODE, on_code)

    calls = []
    for i in range(n):
        emu.memory.write(DESC, b'\x00' * 0x200)
        emu.memory.write(rsp, SENT.to_bytes(8, 'little'))
        uc.reg_write(UC_X86_REG_RSP, rsp & M52)
        uc.reg_write(UC_X86_REG_RCX, CTX)
        uc.reg_write(UC_X86_REG_RDX, DESC)
        try:
            uc.emu_start(G(SIDES[path]['read']), SENT & M52, count=200000)
            ret = uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        except Exception as e:
            calls.append({'ret': 'EXC:%s' % str(e)[:70]})
            break
        rec = {'ret': ret}
        for nm, off, sz in FIELDS:
            v = int.from_bytes(emu.memory.read(DESC + off, sz), 'little')
            # 指针字段（指向解码表）按镜像基址归一化为 RVA —— 两侧镜像基址不同
            if nm == 'dp' and v:
                # 归一化为「表区内偏移」：原始表区起点 0x140096A30，本方 g_PeDecodeTableRegion
                v = (v & M52) - G(SIDES[path]['region'])
            rec[nm] = v
        calls.append(rec)
        cons = rec['cons']
        rp = int.from_bytes(emu.memory.read(CTX + 8, 8), 'little')
        wr64(CTX + 8, rp + cons)
        if ret:
            break
    return calls


def main():
    a = run_side(ORIG)
    b = run_side(REB)
    print('原始侧调用次数 %d，我方侧 %d' % (len(a), len(b)))
    keys = [f[0] for f in FIELDS]
    for i in range(max(len(a), len(b))):
        ra = a[i] if i < len(a) else None
        rb = b[i] if i < len(b) else None
        if ra is None or rb is None:
            print('#%02d 一侧缺调用: orig=%s ours=%s' % (i, bool(ra), bool(rb)))
            continue
        diff = [k for k in keys if ra.get(k) != rb.get(k)] + \
               ([] if ra.get('ret') == rb.get('ret') else ['ret'])
        tag = 'IDENTICAL' if not diff else 'DIFF(%s)' % ','.join(diff)
        print('#%02d %s  ret %s/%s' % (i, tag, ra.get('ret'), rb.get('ret')))
        if diff:
            for k in diff:
                print('      %-8s orig=%-18s ours=%s' % (
                    k, hex(ra[k]) if isinstance(ra.get(k), int) else ra.get(k),
                    hex(rb[k]) if isinstance(rb.get(k), int) else rb.get(k)))
    # 汇总
    n = min(len(a), len(b))
    same = sum(1 for i in range(n)
               if all(a[i].get(k) == b[i].get(k) for k in keys) and a[i].get('ret') == b[i].get('ret'))
    print()
    print('描述符序列一致次数: %d / %d' % (same, max(len(a), len(b))))


if __name__ == '__main__':
    main()
