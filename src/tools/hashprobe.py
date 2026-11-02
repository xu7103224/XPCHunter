# -*- coding: utf-8 -*-
"""反推驱动 Sha1HashToDword 的真实算法：用 (RVA -> 导出名) 与基线 (哈希 -> RVA) 配对。"""
import hashlib
import io
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "tools"))

NT = os.path.join(HERE, "build", "audit", "nt", "ntoskrnl_18362.exe")
BASE = os.path.join(HERE, "build", "audit", "gt_orig_triples.json")


def parse_exports(path):
    data = io.open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    export_rva = struct.unpack_from("<I", data, opt + 112)[0]

    sections = []
    sec = opt + opt_size
    for i in range(num_sections):
        off = sec + 40 * i
        va, vsize = struct.unpack_from("<II", data, off + 12)
        raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
        sections.append((va, vsize, raw_ptr, raw_size))

    def rva_to_off(rva):
        for va, vsize, raw_ptr, raw_size in sections:
            if va <= rva < va + max(vsize, raw_size):
                return raw_ptr + (rva - va)
        return None

    eo = rva_to_off(export_rva)
    num_funcs = struct.unpack_from("<I", data, eo + 20)[0]
    num_names = struct.unpack_from("<I", data, eo + 24)[0]
    addr_funcs, addr_names, addr_ord = struct.unpack_from("<III", data, eo + 28)
    funcs_off = rva_to_off(addr_funcs)
    names_off = rva_to_off(addr_names)
    ord_off = rva_to_off(addr_ord)

    out = []
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", data, names_off + 4 * i)[0]
        no = rva_to_off(name_rva)
        if no is None:
            continue
        end = data.index(b"\0", no)
        name = data[no:end].decode("ascii", "replace")
        oi = struct.unpack_from("<H", data, ord_off + 2 * i)[0]
        if oi >= num_funcs:
            continue
        frva = struct.unpack_from("<I", data, funcs_off + 4 * oi)[0]
        out.append((name, frva))
    return out


def main():
    exports = parse_exports(NT)
    by_rva = {}
    for n, r in exports:
        by_rva.setdefault(r, []).append(n)
    triples = json.load(io.open(BASE, encoding="utf-8"))

    # 收集 (名字, 期望哈希) 样本
    samples = []
    for g, hstr, rstr in triples:
        r = int(rstr, 16)
        if r == 0:
            continue
        for nm in by_rva.get(r, []):
            samples.append((nm, int(hstr, 16)))
        if len(samples) >= 400:
            break
    print("samples:", len(samples))

    def sha1b(b):
        return hashlib.sha1(b).digest()

    def cands(name):
        res = {}
        for tag, s in (("", name), ("lower", name.lower()), ("upper", name.upper())):
            for pre in ("", "\0", "nt"):
                for suf in ("", "\0"):
                    key = tag or "asis"
                    txt = (pre + s + suf)
                    b = sha1b(txt.encode("latin-1"))
                    res["sha1_%s_pre%r_suf%r_le" % (key, pre, suf)] = struct.unpack("<I", b[:4])[0]
        return res

    first = samples[0]
    print("first sample: name=%s expect=0x%08X" % (first[0], first[1]))
    for k, v in cands(first[0]).items():
        if v == first[1]:
            print("  MATCH:", k)
    # 统计每个候选在全部样本上的命中数
    score = {}
    for nm, h in samples[:200]:
        for k, v in cands(nm).items():
            if v == h:
                score[k] = score.get(k, 0) + 1
    print("candidate hit counts (of 200):")
    for k, v in sorted(score.items(), key=lambda kv: -kv[1])[:10]:
        print("  %-40s %d" % (k, v))


if __name__ == "__main__":
    main()
