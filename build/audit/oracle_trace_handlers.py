#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""追踪单条 entry 的 handler 调用链：原始 vs 我方。
对 stream 偏移 0x6 起（48 83 ec 20）这一条，记录 DispatchInstructionDecode 内
每一次 `call qword [rax+idx*8]` 的 idx、目标地址、返回长度、以及 ctx[0] 读指针推进。
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel_sim import KernelSim  # noqa: E402
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_RCX  # noqa: E402

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'

# DispatchInstructionDecode 的 call qword [rax+r8*8] 指令地址
DISP_CALL = {'ORIG': (0x14008C3A6, 0x14008A54C, 0x14008A7E4),
             'MINE': (None, 0x1400541E0, 0x140054180)}

STREAM = bytes.fromhex(
    '48895c2418564883ec2048897c2438488bf265488b3c2588010000'
    '66ff8fe6010000b203e887000000488bd84885c0743548896c2430'
    'e885fba4fff7830c0300')


def find_disp_call(path):
    """在 .text 里找 `42 ff 14 c0`（call qword [rax+r8*8]）。"""
    f = open(path, 'rb').read()
    pe = struct.unpack_from('<I', f, 0x3c)[0]
    nsec = struct.unpack_from('<H', f, pe + 6)[0]
    opt = struct.unpack_from('<H', f, pe + 20)[0]
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        name = f[o:o + 8].rstrip(b'\x00').decode('latin1')
        if name != '.text':
            continue
        vsz, va, rsz, ra = struct.unpack_from('<IIII', f, o + 8)
        seg = f[ra:ra + rsz]
        hits = []
        j = 0
        while True:
            k = seg.find(b'\x42\xff\x14\xc0', j)
            if k < 0:
                break
            hits.append(va + k)
            j = k + 1
        return hits
    return []


def trace(label, path, read_entry_va, init_ctx_va, disp_call_va):
    sim = KernelSim(path)
    sim.skip_stack_cookie_check()
    sim.enable_gt_trace()
    uc = sim.uc
    ctx_va = sim.scratch(0x200)
    entry_va = sim.scratch(0x200)
    sva = sim.scratch(0x2000, STREAM)

    # Init ctx
    sim.call(init_ctx_va, (sva, len(STREAM), 2, 0),
             stack_words=(0, 0, 0, 0, -1 & 0xFFFFFFFFFFFFFFFF, 0, 0, ctx_va))
    # 推进到偏移 0x6（模拟前两条 entry 的推进）
    for skip in (5, 1):
        uc.mem_write(ctx_va + 8, struct.pack('<Q',
                     struct.unpack_from('<Q', uc.mem_read(ctx_va + 8, 8), 0)[0] + skip))

    log = []
    seen = {'n': 0}

    def on_disp(uc_, sim_):
        idx = uc_.reg_read(8) & 0xFFFFFFFF  # R8
        rax = uc_.reg_read(UC_X86_REG_RAX)
        tgt = struct.unpack('<Q', uc_.mem_read(rax + 8 * (idx % 256), 8))[0]
        log.append(f'  handler idx={idx} -> {hex(tgt)}')
        seen['n'] += 1

    sim.intercept(disp_call_va, on_disp)
    kind, res = sim.call(read_entry_va, (ctx_va, entry_va), count=800000)
    b = sim.read(entry_va, 0x120)
    readptr = struct.unpack_from('<Q', sim.read(ctx_va, 0x48), 8)[0]
    print(f'=== {label} ({path}) ===')
    for line in log:
        print(line)
    print(f'  ret={res} consumed f0={struct.unpack_from("<I", b, 0xF0)[0]} '
          f'f38={struct.unpack_from("<I", b, 0x38)[0]} '
          f'f50=0x{struct.unpack_from("<Q", b, 0x50)[0]:x} '
          f'f88=0x{struct.unpack_from("<Q", b, 0x88)[0]:x} '
          f'f78={struct.unpack_from("<I", b, 0x78)[0]} '
          f'f2a={struct.unpack_from("<H", b, 0x2A)[0]} '
          f'readptr_off=0x{(readptr-sva)&0xffffffffffffffff:x}')
    print(f'  notes={sim.notes[:4]}')


def main():
    print('ORIG disp-call hits:', [hex(x) for x in find_disp_call(ORIG)])
    print('MINE disp-call hits:', [hex(x) for x in find_disp_call(MINE)])
    oh = find_disp_call(ORIG)
    mh = find_disp_call(MINE)
    trace('ORIG', ORIG, 0x14008A54C, 0x14008A7E4, oh[1] if len(oh) > 1 else oh[0])
    trace('MINE', MINE, 0x1400541E0, 0x140054180, mh[1] if len(mh) > 1 else mh[0])


if __name__ == '__main__':
    main()