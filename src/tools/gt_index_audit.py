# -*- coding: utf-8 -*-
"""审计我方驱动的 GT 索引表达式：与原驱动 6084 个 GtRead/GtWrite 调用点的立即数比对。

原理：
  1. 原驱动里 GtRead/GtWrite 的索引是第一个参数（ecx/rcx），编译后就是调用点前
     一条指令里的立即数。用 IDA 取全部调用点地址 + 整段 .text 字节，
     在本地把每个调用点前那条指令解出来。
  2. 得到"原驱动用过的全部索引值"集合。
  3. 把我方源码里所有 GT 索引表达式求值，凡是**不在原集合里**的即为可疑
     （BuildHookTable 那种循环变量索引会被单独识别排除）。

校验：用 IDA 已经标注好 `Index` 注释的 500 条样本验证解码器。
"""
import io
import json
import os
import re
import struct

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDA = os.path.join(HERE, "build", "audit", "ida")
TEXT = os.path.join(IDA, "text.json")
XREFS = os.path.join(IDA, "xrefs.json")
SAMPLES = os.path.join(IDA, "gtidx_p0.json")
ENUM = os.path.join(HERE, "XPCHunterDrv", "inc", "xpc_gt_enum.h")
SRC = os.path.join(HERE, "XPCHunterDrv", "src")


def load_text():
    d = json.load(io.open(TEXT, encoding="utf-8"))
    rec = d["result"][0] if isinstance(d, dict) else d[0]
    base = int(rec["addr"], 16)
    data = bytes(int(x, 16) for x in rec["data"].split())
    return base, data


def decode_index_at(buf, s, end):
    """尝试在 s 处解码一条"把立即数写入 ecx/rcx"的指令，返回 (value, length) 或 None。"""
    n = end - s
    b = buf
    # 48 B9 imm64  : mov rcx, imm64
    if n == 10 and b[s] == 0x48 and b[s + 1] == 0xB9:
        return struct.unpack_from("<Q", b, s + 2)[0], 10
    # B9 imm32     : mov ecx, imm32
    if n == 5 and b[s] == 0xB9:
        return struct.unpack_from("<I", b, s + 1)[0], 5
    # 33 C9        : xor ecx, ecx
    if n == 2 and b[s] == 0x33 and b[s + 1] == 0xC9:
        return 0, 2
    # 8D /r        : lea ecx/rcx, [reg+disp]
    for pre in (0, 1):  # 0 = 无 REX, 1 = REX 0x48
        off = s + pre
        if off >= end or b[off] != 0x8D:
            continue
        if pre == 1 and b[s] != 0x48:
            continue
        if off + 1 >= end:
            continue
        modrm = b[off + 1]
        # reg 字段必须是 ecx(001)/rcx；mod=01 → disp8，mod=10 → disp32
        if (modrm & 0x38) != 0x08:
            continue
        mod = modrm >> 6
        if mod == 1 and n == pre + 3:
            return b[off + 2], pre + 3
        if mod == 2 and n == pre + 6:
            return struct.unpack_from("<I", b, off + 2)[0], pre + 6
        # 48 8D 4C 24 xx : lea rcx,[rsp+disp8] 已被上面覆盖
    # 41 8D 4C..   : lea ecx, [r8..+disp8] (REX.B)
    if n == 5 and b[s] == 0x41 and b[s + 1] == 0x8D:
        modrm = b[s + 2]
        if (modrm & 0x38) == 0x08 and (modrm >> 6) == 1:
            return b[s + 3], 5
    if n == 8 and b[s] == 0x41 and b[s + 1] == 0x8D:
        modrm = b[s + 2]
        if (modrm & 0x38) == 0x08 and (modrm >> 6) == 2:
            return struct.unpack_from("<I", b, s + 3)[0], 8
    return None


def index_for_site(buf, base, site):
    s_off = site - base
    if s_off < 16 or s_off >= len(buf):
        return None
    for start in range(s_off - 1, s_off - 16, -1):
        r = decode_index_at(buf, start, s_off)
        if r and r[1] == s_off - start:
            return r[0]
    return None


def collect_original():
    base, buf = load_text()
    d = json.load(io.open(XREFS, encoding="utf-8"))
    sites = []
    for entry in d["result"]:
        for x in entry["data"]:
            sites.append(int(x["addr"], 16))
    sites = sorted(set(sites))
    vals = {}
    undecoded = []
    for a in sites:
        v = index_for_site(buf, base, a)
        if v is None:
            undecoded.append(a)
        else:
            vals.setdefault(v, []).append(a)
    return sites, vals, undecoded, base, buf


def validate(base, buf):
    """用 IDA 标注的 500 条样本验证解码器。"""
    d = json.load(io.open(SAMPLES, encoding="utf-8"))
    ok = bad = skip = 0
    bads = []
    for h in d["hits"]:
        txt = h["matches"][0]["text"]
        m = re.search(r";\s*Index", txt)
        if not m:
            continue
        # 解析指令
        body = txt.split(";")[0]
        im = re.search(r"(?:mov|lea)\s+(?:e|r)cx,\s*(.+)", body)
        if not im:
            continue
        operand = im.group(1).strip()
        if not re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", operand):
            skip += 1
            continue
        expect = int(operand, 0)
        # 样本里的 addr 是那条 mov/lea 指令**自身**的地址（不是调用点），
        # 所以直接在 addr 处按候选长度解码，取第一个长度自洽的结果。
        off = int(h["addr"], 16) - base
        got = None
        for ln in (2, 3, 4, 5, 6, 7, 8, 10):
            r = decode_index_at(buf, off, off + ln)
            if r and r[1] == ln:
                got = r[0]
                break
        if got == expect:
            ok += 1
        else:
            bad += 1
            bads.append((h["addr"], expect, got, txt.strip()))
    print("解码器校验：OK=%d BAD=%d 跳过(非常量)=%d" % (ok, bad, skip))
    for a, e, g, t in bads[:10]:
        print("   %s 期望=%s 实得=%s   %s" % (a, hex(e) if e is not None else e,
                                              hex(g) if g is not None else g, t))
    return bad == 0


def load_enum():
    txt = io.open(ENUM, encoding="utf-8", errors="replace").read()
    name2val = {}
    for m in re.finditer(r'^\s*(Gt[A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,', txt, re.M):
        name2val[m.group(1)] = int(m.group(2), 0)
    for m in re.finditer(r'^#define\s+(Gt[A-Za-z0-9_]+)\s+(Gt[A-Za-z0-9_]+)\s*$', txt, re.M):
        if m.group(2) in name2val:
            name2val[m.group(1)] = name2val[m.group(2)]
    return name2val


def collect_ours(name2val):
    """收集我方源码里所有可静态求值的 GT 索引表达式及其位置。"""
    out = []          # (value, path, line, expr)
    computed = []     # 无法静态求值（含变量/加法）的
    pat = re.compile(r'Gt(Read|Write)\s*\(\s*([^,\)]+?)\s*[,\)]')
    for dp, _, fs in os.walk(SRC):
        for fn in fs:
            if not fn.endswith(".c"):
                continue
            p = os.path.join(dp, fn)
            for i, line in enumerate(io.open(p, encoding="utf-8", errors="replace").read().splitlines(), 1):
                for m in pat.finditer(line):
                    expr = m.group(2).strip()
                    parts = [x.strip() for x in expr.split("|")]
                    vals = []
                    ok = True
                    for x in parts:
                        if x in name2val:
                            vals.append(name2val[x])
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
    sites, vals, undecoded, base, buf = collect_original()
    print("原驱动调用点 %d 个；解出索引 %d 个；无法解码 %d 个"
          % (len(sites), sum(len(v) for v in vals.values()), len(undecoded)))
    good = validate(base, buf)
    if not good:
        print("!! 解码器校验未通过，后续结论不可信")
        return 1

    name2val = load_enum()
    ours, computed = collect_ours(name2val)
    orig_set = set(vals)
    print("\n原驱动用过的不同索引值：%d 个" % len(orig_set))
    print("我方静态索引表达式：%d 处（不同值 %d 个）；无法静态求值：%d 处"
          % (len(ours), len(set(v for v, _, _, _ in ours)), len(computed)))

    missing = {}
    for v, p, i, expr in ours:
        if v not in orig_set:
            missing.setdefault(v, []).append((os.path.relpath(p, HERE), i, expr))
    print("\n=== 我方用到、但原驱动从未作为 GT 索引出现的值（可疑）===")
    if not missing:
        print("  （无）")
    for v in sorted(missing):
        lst = missing[v]
        print("  0x%04X (%d) x%d  首处 %s:%d  %s"
              % (v, v, len(lst), lst[0][0], lst[0][1], lst[0][2]))

    io.open(os.path.join(IDA, "gt_index_audit.json"), "w", encoding="utf-8").write(
        json.dumps({"orig_index_values": sorted(orig_set),
                    "orig_count": len(orig_set),
                    "undecoded_sites": undecoded,
                    "suspicious": {hex(k): v for k, v in missing.items()},
                    "computed_expr_count": len(computed)},
                   indent=1))
    print("\n写出 build/audit/ida/gt_index_audit.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
