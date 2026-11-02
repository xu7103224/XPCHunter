# -*- coding: utf-8 -*-
"""用 capstone 全量反汇编原驱动的 .text，取出每个 GtRead/GtWrite 调用点的索引立即数，
再与我方源码里的 GT 索引表达式比对，找出"我方用到但原驱动从未作为索引出现"的值。

数据来源：
  build/audit/ida/text.json   —— get_bytes 读到的 .text 字节（base 0x140001000）
  build/audit/ida/xrefs.json  —— xref_query 得到的 GtRead/GtWrite 全部调用点
  build/audit/ida/gtidx_p0.json —— IDA 标注 `Index` 的 500 条样本（用于校验）
"""
import io
import json
import os
import re
import sys

import capstone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDA = os.path.join(HERE, "build", "audit", "ida")
TEXT = os.path.join(IDA, "text.json")
XREFS = os.path.join(IDA, "xrefs.json")
SAMPLES = os.path.join(IDA, "gtidx_p0.json")
ENUM = os.path.join(HERE, "XPCHunterDrv", "inc", "xpc_gt_enum.h")
SRC = os.path.join(HERE, "XPCHunterDrv", "src")

ECX = capstone.x86.X86_REG_ECX
RCX = capstone.x86.X86_REG_RCX


def load_text():
    d = json.load(io.open(TEXT, encoding="utf-8"))
    rec = d["result"][0] if isinstance(d, dict) else d[0]
    return int(rec["addr"], 16), bytes(int(x, 16) for x in rec["data"].split())


def build_insn_index(base, buf):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    by_addr = {}
    prev = {}
    order = []
    for ins in md.disasm(buf, base):
        by_addr[ins.address] = ins
        order.append(ins.address)
    for i, a in enumerate(order):
        prev[a] = order[i - 1] if i else None
    return by_addr, prev


def index_before(by_addr, prev, site):
    """从调用点往前找最后一次写 ecx/rcx 的指令，若是常量则返回其值。"""
    a = prev.get(site)
    steps = 0
    while a is not None and steps < 24:
        ins = by_addr[a]
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_REG and op.reg in (ECX, RCX):
                if ins.mnemonic in ("mov", "movzx", "movsxd"):
                    src = ins.operands[1]
                    if src.type == capstone.x86.X86_OP_IMM:
                        return src.imm
                    return None
                if ins.mnemonic == "lea":
                    m = ins.operands[1].mem
                    if m.index == 0 and m.base != 0:
                        return m.disp & 0xFFFFFFFF
                    return None
                if ins.mnemonic == "xor" and ins.operands[1].type == capstone.x86.X86_OP_REG \
                        and ins.operands[1].reg == op.reg:
                    return 0
                return None
        a = prev.get(a)
        steps += 1
    return None


def collect_original(by_addr, prev):
    d = json.load(io.open(XREFS, encoding="utf-8"))
    sites = set()
    for entry in d["result"]:
        for x in entry["data"]:
            sites.add(int(x["addr"], 16))
    vals, undec = {}, []
    for a in sorted(sites):
        v = index_before(by_addr, prev, a)
        if v is None:
            undec.append(a)
        else:
            vals.setdefault(v, []).append(a)
    return sites, vals, undec


def validate(by_addr):
    d = json.load(io.open(SAMPLES, encoding="utf-8"))
    ok = bad = skip = 0
    bads = []
    for h in d["hits"]:
        txt = h["matches"][0]["text"]
        body = txt.split(";")[0]
        im = re.search(r"(?:mov|lea)\s+(?:e|r)cx,\s*(.+?)\s*$", body)
        if not im:
            continue
        operand = im.group(1).strip()
        if not re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", operand):
            skip += 1
            continue
        expect = int(operand, 0)
        ins = by_addr.get(int(h["addr"], 16))
        got = None
        if ins:
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_REG and op.reg in (ECX, RCX):
                    if ins.mnemonic == "mov" and ins.operands[1].type == capstone.x86.X86_OP_IMM:
                        got = ins.operands[1].imm
                    elif ins.mnemonic == "lea":
                        got = ins.operands[1].mem.disp & 0xFFFFFFFF
                    elif ins.mnemonic == "xor":
                        got = 0
        if got == expect:
            ok += 1
        else:
            bad += 1
            bads.append((h["addr"], expect, got, txt.strip()))
    print("capstone 校验：OK=%d BAD=%d 跳过(非常量)=%d" % (ok, bad, skip))
    for a, e, g, t in bads[:8]:
        print("   %s 期望=%s 实得=%s  %s" % (a, hex(e), hex(g) if g is not None else g, t))
    return bad == 0


def load_enum():
    txt = io.open(ENUM, encoding="utf-8", errors="replace").read()
    n2v = {}
    for m in re.finditer(r'^\s*(Gt[A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,', txt, re.M):
        n2v[m.group(1)] = int(m.group(2), 0)
    for m in re.finditer(r'^#define\s+(Gt[A-Za-z0-9_]+)\s+(Gt[A-Za-z0-9_]+)\s*$', txt, re.M):
        if m.group(2) in n2v:
            n2v[m.group(1)] = n2v[m.group(2)]
    return n2v


def strip_comments(text):
    """去掉 /* */ 与 // 注释，避免把注释里提到的字面量当成真实调用。"""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            end = n if j < 0 else j + 2
            out.append("\n" * text.count("\n", i, end))
            i = end
        elif text.startswith("//", i):
            j = text.find("\n", i)
            end = n if j < 0 else j
            out.append("\n" * text.count("\n", i, end))
            i = end
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            seg = text[i:j + 1]
            out.append('""' + "\n" * seg.count("\n"))
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def collect_ours(n2v):
    out, computed = [], []
    pat = re.compile(r'Gt(Read|Write)\s*\(\s*([^,\)]+?)\s*[,\)]')
    for dp, _, fs in os.walk(SRC):
        for fn in fs:
            if not fn.endswith(".c"):
                continue
            p = os.path.join(dp, fn)
            raw = io.open(p, encoding="utf-8", errors="replace").read()
            clean = strip_comments(raw)
            for i, line in enumerate(clean.splitlines(), 1):
                for m in pat.finditer(line):
                    expr = m.group(2).strip()
                    vals, ok = [], True
                    for x in (y.strip() for y in expr.split("|")):
                        if x in n2v:
                            vals.append(n2v[x])
                        elif re.fullmatch(r'0x[0-9A-Fa-f]+|\d+', x):
                            vals.append(int(x, 0))
                        else:
                            ok = False
                            break
                    if not ok:
                        computed.append((p, i, expr))
                        continue
                    v = 0
                    for x in vals:
                        v |= x
                    out.append((v, p, i, expr))
    return out, computed


def main():
    base, buf = load_text()
    by_addr, prev = build_insn_index(base, buf)
    print("反汇编出 %d 条指令" % len(by_addr))
    if not validate(by_addr):
        print("!! 校验未通过")
        return 1

    sites, vals, undec = collect_original(by_addr, prev)
    print("原驱动 GT 调用点 %d 个；解出索引 %d 个；未解出 %d 个"
          % (len(sites), sum(len(v) for v in vals.values()), len(undec)))

    n2v = load_enum()
    ours, computed = collect_ours(n2v)
    orig = set(vals)
    print("原驱动用过的不同索引值 %d 个；我方静态索引表达式 %d 处（不同值 %d），"
          "无法静态求值 %d 处" % (len(orig), len(ours),
                                  len(set(v for v, _, _, _ in ours)), len(computed)))

    missing = {}
    for v, p, i, expr in ours:
        if v in orig:
            continue
        # 排除两类已知的、非缺陷的差异：
        #  0x4E00-0x4FFF 是我方新增的诊断槽（命令统计/环境导出），原始当然没有；
        #  0x4158-0x447C 是 BuildHookTable 用循环变量写的那批 [hash,rva,va] 三元组，
        #    原驱动同样用循环写，所以不会以字面量形式出现在调用点里。
        if 0x4E00 <= v <= 0x4FFF or 0x4158 <= v <= 0x447C:
            continue
        missing.setdefault(v, []).append((os.path.relpath(p, HERE), i, expr))
    print("\n=== 我方用到、但原驱动从未作为 GT 索引出现的值"
          "（已排除诊断槽 0x4E00+ 与三元组区 0x4158-0x447C）===")
    if not missing:
        print("  （无）")
    for v in sorted(missing):
        lst = missing[v]
        print("  0x%04X (%d) x%-3d 首处 %s:%d  %s"
              % (v, v, len(lst), lst[0][0], lst[0][1], lst[0][2]))
    print("\n共 %d 个可疑值，涉及 %d 处引用"
          % (len(missing), sum(len(v) for v in missing.values())))

    io.open(os.path.join(IDA, "gt_index_audit.json"), "w", encoding="utf-8").write(
        json.dumps({"orig_distinct": len(orig), "orig_values": sorted(orig),
                    "sites": len(sites), "undecoded": len(undec),
                    "suspicious": {hex(k): v for k, v in missing.items()}},
                   indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
