# 从 IDA 直接提取函数体内构造的 UTF-16 字符串常量（按栈写入顺序与真实偏移还原）
# 做法：反编译/反汇编同一函数，取每条"写栈槽立即数"指令的**真实栈偏移**与值，
#       按偏移升序拼成字节流再按 UTF-16 解码。比按 var_XX 名猜偏移可靠。
import os
import re
import struct
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)
import idapro  # noqa: E402

I64 = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\samples\PCHunter_2024.09.02\View++_Driver64.sys.i64"
TARGETS = [(n, int(a, 16)) for n, a in (x.split('=') for x in sys.argv[1:])]

idapro.open_database(I64, True)
import idautils, idc, ida_funcs, ida_ua, ida_lines  # noqa: E402

for name, ea in TARGETS:
    f = ida_funcs.get_func(ea)
    if not f:
        print("%s: 非函数" % name)
        continue
    items = []
    for h in idautils.Heads(f.start_ea, f.end_ea):
        txt = ida_lines.tag_remove(idc.generate_disasm_line(h, 0) or '')
        m = re.match(r'^mov\s+(?:dword ptr |word ptr |byte ptr )?\[(\w+)([+-][0-9A-F]+h)?\],\s*([0-9A-F]+)h', txt)
        if not m:
            continue
        reg, disp, val = m.group(1), m.group(2), int(m.group(3), 16)
        if reg != 'rbp':
            continue
        # 位移：如 +57h+var_70 这种 IDA 复合名，改用 insn 的 op 结构取真实 addr
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, h):
            continue
        # op0 = 目标（displ），op1 = 立即数
        if insn.ops[0].type != ida_ua.o_displ or insn.ops[1].type != ida_ua.o_imm:
            continue
        off = insn.ops[0].addr
        size = insn.ops[0].dtype if insn.ops[0].dtype in (1, 2, 4) else 4
        items.append((off, insn.ops[1].value, size))
    if not items:
        print("%s: 未找到栈立即数写入" % name)
        continue
    items.sort(key=lambda x: x[0])
    base = items[0][0]
    buf = bytearray()
    for off, val, size in items:
        pos = off - base
        if size == 1:
            data = struct.pack('<B', val & 0xFF)
        elif size == 2:
            data = struct.pack('<H', val & 0xFFFF)
        else:
            data = struct.pack('<I', val & 0xFFFFFFFF)
        if pos > len(buf):
            buf += b'\0' * (pos - len(buf))
        buf += data
    s = bytes(buf).decode('utf-16-le', errors='replace').split('\x00')[0]
    print("%-34s -> %r" % (name, s))

idapro.close_database()