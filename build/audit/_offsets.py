# 提取函数内所有内存操作数的 [基址+位移]，按基址寄存器归组，用于核对结构体偏移
# 用法: python _offsets.py <FuncName> [FuncName2 ...]
import json
import os
import re
import sys

IDA_LIB = r"E:\DevTools\IDA Professional 9.2"
sys.path.insert(0, os.path.join(IDA_LIB, "idalib", "python"))
os.environ.setdefault("IDADIR", IDA_LIB)

import idapro  # noqa: E402

ROOT = r"E:\Work\Dev\Windows\wmprotected\APK\XPCHunter"
I64 = os.path.join(ROOT, "samples", "PCHunter_2024.09.02", "View++_Driver64.sys.i64")

names = sys.argv[1:]
orig = json.load(open(os.path.join(ROOT, "build", "audit", "_orig_funcs_ida.json"), encoding="utf-8"))

idapro.open_database(I64, True)

import ida_funcs, ida_lines, idautils, idc, ida_ua  # noqa: E402

PAT = re.compile(r"^([a-z]+)\s+.*?\[([a-z0-9]+)(?:\+([0-9A-F]+)h)?\]", re.I)


def ops(ea):
    """返回该指令中所有内存操作数 (基址, 位移)"""
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        return []
    out = []
    for i in range(6):
        op = insn.ops[i]
        if op.type == 0:
            break
        if op.type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ):
            base = insn.ops[op.phrase // 8].reg if op.phrase else -1
            out.append((ida_ua.print_operand(ea, i), base, op.addr, op.type))
    return out


for nm in names:
    cands = [it for it in orig if it["name"] == nm]
    if not cands:
        print("NOT FOUND:", nm)
        continue
    f = ida_funcs.get_func(cands[0]["start"])
    print("=== %s 0x%X (%d) ===" % (nm, f.start_ea, cands[0]["size"]))
    # 只看前 20 条（序言，用于识别参数落到哪个寄存器）
    for h in list(idautils.Heads(f.start_ea, f.end_ea))[:14]:
        print("  P 0x%X: %s" % (h, ida_lines.tag_remove(idc.generate_disasm_line(h, 0))))

idapro.close_database()
