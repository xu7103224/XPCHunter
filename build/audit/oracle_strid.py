#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线模拟 FindKernelPESectionByType，用真实 ntoskrnl.exe 求其返回值。

GT 输入（与实机一致）：
  0x20 = PE 文件缓冲基址（本脚本把真实 ntoskrnl.exe 字节映射到 SCRATCH 区）
  0x21 = PE 文件大小
  0x41D1 / 0x41D4 = 该函数参数（文件内偏移）
输出：函数返回的 Entry[0x70]（= Str 步长），并验证 0x41D4 的返回值 - 0x41D1 的返回值
      是否等于 472（.rdata 中 A/B 的真实间距）。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from kernel_sim import KernelSim, SCRATCH_BASE  # noqa: E402


def main():
    pe_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'ntoskrnl_guest.exe')
    data = open(pe_path, 'rb').read()
    print('PE file size = %d (%#x)' % (len(data), len(data)))

    for drv, label in (('samples/PCHunter_2024.09.02/View++_Driver64.sys', 'ORIG'),):
        sim = KernelSim(drv)
        sim.skip_stack_cookie_check()
        sim.enable_gt_trace()
        # 把 PE 文件映射到 SCRATCH
        base = sim.scratch((len(data) + 0xFFF) & ~0xFFF)
        sim.uc.mem_write(base, data)
        sim.set_gt(0x20, base)
        sim.set_gt(0x21, len(data))
        sim.set_gt(0x41D1, 0x1B9600)  # 实机值
        sim.set_gt(0x41D4, 0x1B90E0)  # 实机值
        sim.set_gt(0x914, 19045)

        # 原始 FindKernelPESectionByType @ 0x14007A6B8
        kind, r1 = sim.call(0x14007A6B8, (0x41D1,), count=2000000)
        print('%s FindKernelPESectionByType(0x41D1) -> %s %s' % (
            label, kind, hex(r1) if kind == 'OK' else r1))
        kind, r2 = sim.call(0x14007A6B8, (0x41D4,), count=2000000)
        print('%s FindKernelPESectionByType(0x41D4) -> %s %s' % (
            label, kind, hex(r2) if kind == 'OK' else r2))
        if kind == 'OK':
            print('  stride = ST2 - ST1 =', (r2 - r1) & 0xFFFFFFFF,
                  '(需要 472)')
        print('  notes:', sim.notes[:3])


if __name__ == '__main__':
    main()