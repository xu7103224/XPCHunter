#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
差分 oracle：在同一模拟器、同一输入字节流上，分别运行
  - 原始驱动 ReadPESectionEntry @ 0x14008A54C
  - 我方驱动 ReadPESectionEntry
逐条 dump 描述符 +0x118/+6（type）、+0xF0（消费）、+0x50、+0x38、+0x88、+0x78、
ctx+0x08（ReadPtr），从而定位解码器第一个分歧点。

用法:
  python oracle_read_entries.py [stream_hex_file] [n_entries]
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel_sim import KernelSim, SIM_BASE, SCRATCH_BASE  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_RIP, UC_X86_REG_RSP,
)

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'

# 原始地址（我方地址由 --mine-rva 参数给出）
READ_ENTRY_ORIG = 0x14008A54C
INIT_CTX_ORIG = 0x14008A7E4


def make_sim(path):
    sim = KernelSim(path)
    sim.skip_stack_cookie_check()
    sim.enable_gt_trace()
    return sim


def dump_one(sim, read_entry_va, init_ctx_va, stream_va, size, n_entries, ctx_va=None,
             entry_va=None):
    """调用 InitPESectionReadContext(stream, size, 2,0,-1,0,0, ctx) 后循环 ReadPESectionEntry。"""
    uc = sim.uc
    if ctx_va is None:
        ctx_va = sim.scratch(0x200)
    if entry_va is None:
        entry_va = sim.scratch(0x200)

    # InitPESectionReadContext(Base, Size, Mode, Param5, ExtraField(stack), Param6, Param7, ctx(stack))
    # 签名: (rcx Base, edx Size, r8d Mode, r9 Param5, [rsp+0x20]=ExtraField, [rsp+0x28]=Param6,
    #        [rsp+0x30]=Param7, [rsp+0x38]=ctx)
    # stack_words[i] 落在 [rsp+8+8i]（rsp[0]=返回地址）。
    # x64 快速调用：param4(ExtraField) 在 [rsp+0x28]=i4，param5 在 i5，param6 在 i6，
    # param7(ctx) 在 [rsp+0x40]=i7。
    sim.call(init_ctx_va, (stream_va, size, 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx_va))

    out = []
    for i in range(n_entries):
        kind, res = sim.call(read_entry_va, (ctx_va, entry_va), count=400000)
        rec = {'i': i, 'ret': res if kind == 'OK' else kind}
        try:
            b = sim.read(entry_va, 0x120)
            ctxb = sim.read(ctx_va, 0x48)
            readptr = struct.unpack_from('<Q', ctxb, 8)[0]
            rec['readptr'] = readptr
            rec['stream_off'] = (readptr - stream_va) & 0xFFFFFFFFFFFFFFFF
            rec['f0'] = struct.unpack_from('<I', b, 0xF0)[0]
            rec['f50'] = struct.unpack_from('<Q', b, 0x50)[0]
            rec['f38'] = struct.unpack_from('<I', b, 0x38)[0]
            rec['f88'] = struct.unpack_from('<Q', b, 0x88)[0]
            rec['f78'] = struct.unpack_from('<I', b, 0x78)[0]
            t118 = struct.unpack_from('<Q', b, 0x118)[0]
            rec['type'] = struct.unpack_from('<H', sim.read(t118, 8), 6)[0] if t118 else None
            rec['t118_delta'] = (t118 - SIM_BASE) if t118 else None
            rec['byte_at_readptr'] = sim.read(readptr, 1)[0] if readptr else None
            # 模拟调用方推进读指针（原始 ReadPESectionEntry 不回写 ctx+0x08）
            newptr = (readptr + rec['f0']) & 0xFFFFFFFFFFFFFFFF
            sim.uc.mem_write(ctx_va + 8, struct.pack('<Q', newptr))
        except Exception as e:  # noqa: BLE001
            rec['err'] = str(e)
        out.append(rec)
    return out


def fmt(rec):
    if 'err' in rec:
        return f"#{rec['i']:2d} ERR {rec['err']} ret={rec['ret']}"
    return ("#{:2d} off=0x{:<6x} b0=0x{:02x} f0={:<2d} type=0x{:x} f50=0x{:x} f38={:<4d} "
            "f88=0x{:x} f78={:<4d} t118=+0x{:x} ret={}").format(
        rec['i'], rec['stream_off'], rec.get('byte_at_readptr') or 0, rec['f0'],
        rec['type'] or 0, rec['f50'], rec['f38'], rec['f88'], rec['f78'],
        rec['t118_delta'] or 0, rec['ret'])


def main():
    stream_file = sys.argv[1] if len(sys.argv) > 1 else None
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    if stream_file:
        with open(stream_file, 'rb') as fh:
            stream = fh.read()
    else:
        # 用 nt! 里的真实流：从 nt+0x66EDC0 起（guest 读到的字节）
        stream = bytes.fromhex(
            '48895c2418564883ec2048897c2438488bf265488b3c2588010000'
            '66ff8fe6010000b203e887000000488bd84885c0743548896c2430'
            'e885fba4fff7830c0300')
    print(f'stream {len(stream)} bytes: {stream.hex()}')

    for label, path, re_va, ic_va in (
        ('ORIG', ORIG, READ_ENTRY_ORIG, INIT_CTX_ORIG),
        ('MINE', MINE, 0x1400541E0, 0x140054180),
    ):
        sim = make_sim(path)
        sva = sim.scratch(0x2000, stream)
        print(f'\n=== {label} {path} ===')
        try:
            recs = dump_one(sim, re_va, ic_va, sva, len(stream), n)
            for r in recs:
                print('  ' + fmt(r))
        except Exception as e:  # noqa: BLE001
            print('  EXC', e)
            print('  notes:', sim.notes[:8])


if __name__ == '__main__':
    main()