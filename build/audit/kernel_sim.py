#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在 Unicorn 里执行 PCHunter 驱动代码，并观察运行时行为。

关键设计：**模拟基址 = 0x140000000 = IDA 原始基址**。
这样模拟器里的地址与 IDA 数据库、与源码注释里的 `对应原始驱动 0x...` 完全一致，
任何观察结果都能直接回填到逆向结论里。

可观察的能力：
  - 拦截内核 API（导入桩）与指定的内部函数，记录调用参数/返回；
  - 拦截 GtRead / GtWrite（本驱动自己的全局表访问函数），
    **在运行时记录每一次 GT 索引读写** —— 这正是静态分析最难确证的部分；
  - 记录执行过的基本块，用于确认控制流走向。

已知环境限制：Unicorn 2.1.4 无法在 ≥0xFFFF800000000000 的内核高地址区执行代码，
故模拟基址取 0x140000000（< 0x7FFFFF000000）。
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_map import MappedImage

from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_BLOCK,
                     UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                     UC_HOOK_MEM_FETCH_UNMAPPED)
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP,
)

MASK64 = (1 << 64) - 1
ARGREGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]

SIM_BASE = 0x140000000          # = IDA 原始基址（便于与逆向结论对照）
STACK_BASE = 0x20000000
STACK_SIZE = 0x100000
SCRATCH_BASE = 0x30000000
SCRATCH_SIZE = 0x1000000
API_STUB_BASE = 0x40000000
API_STUB_SIZE = 0x100000
SENTINEL = 0x4F000000           # ret 落点（emu_start 的 until）

# 驱动自身的全局表访问函数（来自源码注释，可在模拟器里拦截以观察运行时索引）
ADDR_GT_READ = 0x140029EFC
ADDR_GT_WRITE = 0x140029FF4
ADDR_SECURITY_CHECK_COOKIE = 0x14008C8B0


class KernelSim:
    def __init__(self, path, image_base=SIM_BASE, verbose=False):
        self.img = MappedImage(path, image_base)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.verbose = verbose

        self.api_calls = []        # [(name, [a0..a3])]
        self.api_returns = {}      # name -> int | callable(sim)->int
        self.gt_reads = []         # [(index, ret)]
        self.gt_writes = []        # [(index, value)]
        self.blocks = []           # 执行过的块
        self.notes = []            # 未映射访问等告警
        self.intercepts = {}       # 地址 -> handler(uc, sim)

        self._gt_values = {}       # 供 GtRead 返回值的注入表
        self._map_all()
        self._install_hooks()

    # ---------------- 内存 ----------------
    def _map_all(self):
        uc = self.uc
        sz = (self.img.size + 0xFFF) & ~0xFFF
        uc.mem_map(self.img.base, sz)
        uc.mem_write(self.img.base, bytes(self.img.image))
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.mem_map(SCRATCH_BASE, SCRATCH_SIZE)
        uc.mem_map(API_STUB_BASE, API_STUB_SIZE)
        # 导入表重定向到 API 桩区（pe_map 把 IAT 指向 STUB_BASE）
        self._remap_imports()

    def _remap_imports(self):
        idx = 0
        for (dll, fname), rva in self.img.import_thunks.items():
            stub = API_STUB_BASE + idx * 0x10
            idx += 1
            self.img.stubs[fname] = stub
            self.img.stub_names[stub] = fname
            self.uc.mem_write(self.img.va_of(rva), struct.pack('<Q', stub))
            self.uc.mem_write(stub, b'\xC3')
        uc = self.uc
        # 哨兵页
        uc.mem_map(SENTINEL & ~0xFFF, 0x1000)
        uc.mem_write(SENTINEL, b'\xF4')

    # ---------------- 钩子 ----------------
    def _install_hooks(self):
        uc = self.uc

        def on_block(uc_, address, size, user_data):
            self.blocks.append(address)
            h = self.intercepts.get(address)
            if h is not None:
                h(uc_, self)
                return
            name = self.img.stub_names.get(address)
            if name is not None:
                self._on_api_call(uc_, name)

        uc.hook_add(UC_HOOK_BLOCK, on_block)

        def on_bad(uc_, access, address, size, value, user_data):
            self.notes.append(f'未映射访问 addr={hex(address)} size={size} rip={hex(uc_.reg_read(UC_X86_REG_RIP))}')
            return False

        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_bad)
        uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_bad)
        uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, on_bad)

    def _on_api_call(self, uc, name):
        args = [uc.reg_read(r) for r in ARGREGS]
        self.api_calls.append((name, args))
        if self.verbose:
            print(f'    [API] {name}({", ".join(hex(a) for a in args)})')
        spec = self.api_returns.get(name, 0)
        ret = spec(self) if callable(spec) else spec
        uc.reg_write(UC_X86_REG_RAX, ret & MASK64)
        self._do_ret(uc)

    @staticmethod
    def _do_ret(uc):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack('<Q', uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    # ---------------- 可注入的截获 ----------------
    def intercept(self, addr, handler):
        self.intercepts[addr] = handler

    def enable_gt_trace(self):
        """拦截 GtRead/GtWrite，记录运行时索引。"""
        def gt_read(uc, sim):
            idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            val = sim._gt_values.get(idx, 0)
            sim.gt_reads.append((idx, val))
            if sim.verbose:
                print(f'    [GtRead ] {hex(idx)} -> {hex(val)}')
            uc.reg_write(UC_X86_REG_RAX, val & MASK64)
            sim._do_ret(uc)

        def gt_write(uc, sim):
            idx = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF
            val = uc.reg_read(UC_X86_REG_RDX) & MASK64
            sim.gt_writes.append((idx, val))
            sim._gt_values[idx] = val
            if sim.verbose:
                print(f'    [GtWrite] {hex(idx)} = {hex(val)}')
            uc.reg_write(UC_X86_REG_RAX, val & MASK64)
            sim._do_ret(uc)

        self.intercept(ADDR_GT_READ, gt_read)
        self.intercept(ADDR_GT_WRITE, gt_write)

    def skip_stack_cookie_check(self):
        """让 __security_check_cookie 直接返回，避免模拟环境下误判 GS 失败。"""
        def nop(uc, sim):
            sim._do_ret(uc)
        self.intercept(ADDR_SECURITY_CHECK_COOKIE, nop)

    # ---------------- 执行 ----------------
    def call(self, va, args=(), count=200000, timeout=0, stack_words=()):
        uc = self.uc
        rsp = STACK_BASE + STACK_SIZE // 2
        # 栈内容：返回地址 + 可选额外字（模拟栈上传参）
        uc.mem_write(rsp, struct.pack('<Q', SENTINEL))
        for i, w in enumerate(stack_words):
            uc.mem_write(rsp + 8 + i * 8, struct.pack('<Q', w & MASK64))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        for i, a in enumerate(args[:4]):
            uc.reg_write(ARGREGS[i], a & MASK64)
        try:
            uc.emu_start(va, SENTINEL, timeout=timeout, count=count)
        except UcError as e:
            return ('ERR', str(e))
        return ('OK', uc.reg_read(UC_X86_REG_RAX))

    # ---------------- 工具 ----------------
    def scratch(self, size=0x1000, init=None):
        if not hasattr(self, '_soff'):
            self._soff = 0x1000
        a = SCRATCH_BASE + self._soff
        self._soff += (size + 0xFFF) & ~0xFFF
        if init:
            self.uc.mem_write(a, init)
        return a

    def set_gt(self, index, value):
        self._gt_values[index & 0xFFFFFFFF] = value & MASK64

    def read(self, va, n):
        return bytes(self.uc.mem_read(va, n))


def demo():
    path = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
    sim = KernelSim(path, verbose=True)
    print(f'模拟基址 {hex(sim.img.base)}（= IDA 原始基址）')
    print(f'镜像大小 {hex(sim.img.size)}，重定位 {sim.img.relocs_applied} 条（基址相同故为 0）')
    print(f'导入桩 {len(sim.img.stubs)} 个 -> API 区 {hex(API_STUB_BASE)}')
    sim.skip_stack_cookie_check()
    sim.enable_gt_trace()

    # 试跑一个纯函数：RotateLeft64Impl @ 0x140001711（rol rdx,cl; mov rax,rdx）
    print('\n--- RotateLeft64Impl 0x140001711 ---')
    kind, res = sim.call(0x140001711, (0, 0x123456789ABCDEF0, 8))
    print('  返回', kind, hex(res) if kind == 'OK' else res)
    print('  块数', len(sim.blocks))


if __name__ == '__main__':
    demo()