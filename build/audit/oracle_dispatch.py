#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线验证 DispatchDeviceControl 的分派逻辑（不依赖实机）。

构造一个按协议加密的 0x30 请求，在模拟器里调用我方的 DispatchDeviceControl，
检查它是否：
  1. 接受正确的 IoControlCode（= GT[0x1E0]）
  2. 拒绝错误 IoControlCode
  3. 解密后识别 Magic
  4. MD5 校验通过
  5. 分派到正确的命令表项

原始驱动的对应地址：0x1400823EC。
"""
import os, sys, struct, re, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, '..', '..'))
from kernel_sim import KernelSim, MASK64
from unicorn.x86_const import (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
                               UC_X86_REG_R9, UC_X86_REG_RAX, UC_X86_REG_RSP)

MINE = os.path.join(HERE, '..', '..', 'build', 'bin', 'Release', 'x64', 'XPCHunterDrv.sys')
MAP = os.path.join(HERE, '..', 'bin', 'Release', 'x64', 'XPCHunterDrv.map')

HTTP = None


def sym(n, default=None):
    for ln in open(MAP, encoding='utf-8', errors='ignore'):
        m = re.match(r'\s+000[123]:[0-9a-f]{8}\s+' + n + r'\s+([0-9a-f]{16})\s+\S+', ln)
        if m:
            return int(m.group(1), 16)
    return default


def derive(name):
    """与 Protocol.c 的 XpchDeriveParams 等价"""
    dest = "\\\\.\\" + name
    n = len(dest)
    raw = dest.encode('utf-16-le')
    edi = 0x20
    for i in range(n - 4):
        w = raw[8 + i * 2] | (raw[9 + i * 2] << 8)
        edi = (w ^ ((w + edi) & 0xFFFFFFFF)) & 0xFFFFFFFF
    first = raw[8]
    ioctl = (4 * (first | ((edi << 14) & 0xFFFFFFFF))) & 0xFFFFFFFF
    key = 0x20
    for c in raw[8:2 * n]:
        if c:
            key ^= c
        else:
            key = ((key >> 4) + 16 * key) & 0xFF
    return ioctl, key


def build_request(cmd, out_ptr, out_size, ctx_ptr=0, ctx_size=0, extra=0, key=0xCF):
    req = bytearray(0x30)
    struct.pack_into('<I', req, 0x00, 0x20240810)
    struct.pack_into('<I', req, 0x04, cmd)
    struct.pack_into('<Q', req, 0x08, out_ptr)
    struct.pack_into('<Q', req, 0x10, ctx_ptr)
    struct.pack_into('<Q', req, 0x18, extra)
    struct.pack_into('<I', req, 0x20, out_size)
    struct.pack_into('<I', req, 0x24, ctx_size)
    digest = hashlib.md5(bytes(req[:0x28])).digest()
    struct.pack_into('<I', req, 0x28, struct.unpack('<I', digest[:4])[0])
    for i in range(0x30):
        req[i] = (~(req[i] ^ key)) & 0xFF
    return bytes(req)


def run(cmd=0x24, ioctl=None, out_size=4, key=0xCF, gt304=1):
    ioctl_true, key_true = derive("View++ByLinxer")
    if ioctl is None:
        ioctl = ioctl_true

    sim = KernelSim(MINE)
    sim.skip_stack_cookie_check()

    # GT 拦截：GtRead / GtWrite
    reads = []
    writes = []

    def gr(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        reads.append(i)
        uc.reg_write(UC_X86_REG_RAX, s._gt_values.get(i, 0) & MASK64)
        s._do_ret(uc)

    def gw(uc, s):
        i = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
        v = uc.reg_read(UC_X86_REG_RDX) & MASK64
        writes.append((i, v))
        s._gt_values[i] = v
        uc.reg_write(UC_X86_REG_RAX, v)
        s._do_ret(uc)

    sim.intercept(sym('GtRead'), gr)
    sim.intercept(sym('GtWrite'), gw)

    # 关键 GT 槽
    sim.set_gt(0x1E0, ioctl_true)      # 期望的 IoControlCode
    sim.set_gt(0x1E1, key_true)        # 解密密钥
    sim.set_gt(0x304, gt304)           # 驱动就绪
    sim.set_gt(0x353, 0)
    sim.set_gt(0x355, 0)               # 重入锁
    # 命令表：GT[0x921 + (cmd-0x20)] = 假处理器地址。用一个立即返回 1 的桩。
    stub = sim.scratch(0x1000)
    # xor eax,eax; inc eax; ret   → 返回 1
    sim.uc.mem_write(stub, bytes([0x31, 0xC0, 0xFF, 0xC0, 0xC3]))
    sim.set_gt(0x921 + (cmd - 0x20), stub)
    sim._stub_addr = stub

    # 输出缓冲
    outbuf = sim.scratch(0x100)
    reqbuf = sim.scratch(0x100)
    req = build_request(cmd, outbuf, out_size, key=key)
    sim.uc.mem_write(reqbuf, req)

    # 伪造 IRP：IoGetCurrentIrpStackLocation 返回 Irp+0x??。
    # 简化：直接 hook 掉 IoGetCurrentIrpStackLocation 让它返回我们准备的结构。
    # 先找它的导入地址。
    fn = sym('DispatchDeviceControl')
    if not fn:
        print('找不到 DispatchDeviceControl 符号'); return None

    # 构造 IRP：+0x18 SystemBuffer，+0xB8 是 IO_STACK_LOCATION*
    irp = sim.scratch(0x200)
    iosl = sim.scratch(0x100)
    sim.uc.mem_write(irp + 0x18, struct.pack('<Q', reqbuf))
    sim.uc.mem_write(irp + 0xB8, struct.pack('<Q', iosl))
    chk = struct.unpack('<Q', sim.read(irp + 0xB8, 8))[0]
    # IO_STACK_LOCATION: +0x10 = DeviceIoControl
    #   Length(4) @ +0x10,  InputBufferLength(4) @ +0x10+8, OutputBufferLength @ +0x10+0x10
    # _IO_STACK_LOCATION layout (x64):
    #   +0x00 MajorFunction(1) MinorFunction(1) Flags(1) Control(1)
    #   +0x08 Parameters union -> DeviceIoControl:
    #         +0x08 OutputBufferLength (4)
    #         +0x10 InputBufferLength  (4)
    #         +0x18 IoControlCode      (4)
    #         +0x20 Type3InputBuffer   (8)
    sim.uc.mem_write(iosl + 0x00, struct.pack('<BBBB', 0x0E, 0, 0, 0))       # IRP_MJ_DEVICE_CONTROL
    # 注意对齐：+0x08 OutputBufferLength(4)、+0x0C 填充、+0x10 InputBufferLength(4)
    sim.uc.mem_write(iosl + 0x08, struct.pack('<I', 0x30))   # OutputBufferLength
    sim.uc.mem_write(iosl + 0x10, struct.pack('<I', 0x30))   # InputBufferLength
    sim.uc.mem_write(iosl + 0x18, struct.pack('<I', ioctl))                  # IoControlCode

    # IoGetCurrentIrpStackLocation(RCX=Irp) → 返回 Irp+0xB8 的值
    def get_stack(uc, s):
        p = uc.reg_read(UC_X86_REG_RCX)
        v = struct.unpack('<Q', uc.mem_read(p + 0xB8, 8))[0]
        uc.reg_write(UC_X86_REG_RAX, v)
        s._do_ret(uc)

    iosl_fn = sym('IoGetCurrentIrpStackLocation')

    # IoCompleteRequest 空实现
    icr = sym('IoCompleteRequest')
    if icr:
        sim.intercept(icr, lambda uc, s: s._do_ret(uc))

    # 命令处理桩：任何调用都返回 1（模拟处理器成功）
    def stub_hook(uc, st):
        uc.reg_write(UC_X86_REG_RAX, 1)
        st._do_ret(uc)
    sim.intercept(stub, stub_hook)

    kind, status = sim.call(fn, (0, irp), count=20000000)
    gt_reads_after = [i for i in reads if i >= 0x900]
    return {
        'kind': kind,
        'status': status,
        'gt_reads_high': sorted(set(gt_reads_after))[:10],
        'gt_writes': writes[:10],
        'outbuf': bytes(sim.read(outbuf, 16)),
    }


if __name__ == '__main__':
    ioctl_true, key_true = derive("View++ByLinxer")
    print('derive: ioctl=0x%08X key=0x%02X' % (ioctl_true, key_true))
    print()

    fails = 0

    def check(name, cond, detail=''):
        global fails
        print('  [%s] %-46s %s' % ('PASS' if cond else 'FAIL', name, detail))
        if not cond:
            fails += 1

    print('=== case 1: correct ioctl + cmd 0x24 -> must succeed ===')
    r = run(cmd=0x24)
    check('status == STATUS_SUCCESS', r['status'] == 0, hex(r['status']))
    check('command table entry GT[0x925] was read', 0x925 in r['gt_reads_high'],
          str([hex(x) for x in r['gt_reads_high']]))
    check('reentry lock GT[0x355] taken and released',
          (0x355, 1) in r['gt_writes'] and (0x355, 0) in r['gt_writes'],
          str([(hex(a), b) for a, b in r['gt_writes']]))

    print()
    print('=== case 2: wrong ioctl -> must be rejected ===')
    r = run(cmd=0x24, ioctl=0x12345678)
    check('status == STATUS_INVALID_PARAMETER', r['status'] == 0xC000000D,
          hex(r['status']))
    check('no command table access', 0x925 not in r['gt_reads_high'])

    print()
    print('=== case 3: wrong key -> must be rejected ===')
    r = run(cmd=0x24, key=0x00)
    check('status == STATUS_INVALID_PARAMETER', r['status'] == 0xC000000D,
          hex(r['status']))
    check('no command table access', 0x925 not in r['gt_reads_high'])

    print()
    print('=== case 4: out-of-range command 0x13B -> must be rejected ===')
    r = run(cmd=0x13B)
    check('status == STATUS_INVALID_PARAMETER', r['status'] == 0xC000000D,
          hex(r['status']))

    print()
    print('RESULT:', 'ALL PASS' if fails == 0 else '%d FAILURES' % fails)
    raise SystemExit(0 if fails == 0 else 1)