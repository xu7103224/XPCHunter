# -*- coding: utf-8 -*-
"""从 ntoskrnl.exe 的导出表建立 name -> (rva, sha1_dword_hash) 映射。

用途：GT[0x4158+3k+2] 那一批槽存的是"按名字哈希查出来的 ntoskrnl 导出地址"，
     GT[0x4158+3k] 存的是预计算的哈希。有了这张映射就能：
       1) 把每个哈希翻译回真实函数名（现有 enum 里的名字多为猜测，不可信）；
       2) 用原始驱动的基线 gt_orig_triples.json 反向核对哈希算法是否正确。

哈希算法（与驱动 Sha1HashToDword 一致）：SHA1(ASCII 名字) 取前 4 字节按小端读成 ULONG。
"""
import hashlib
import io
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NT = os.path.join(HERE, "build", "audit", "nt", "ntoskrnl_18362.exe")
OUT = os.path.join(HERE, "build", "audit", "nt", "nt_exports.json")


def sha1_dword(name: str) -> int:
    d = hashlib.sha1(name.encode("ascii", "replace")).digest()
    return struct.unpack("<I", d[:4])[0]


def parse_exports(path):
    data = io.open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not a PE"
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic == 0x20B, "not PE32+"
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    export_rva, export_size = struct.unpack_from("<II", data, opt + 112)

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
    num_funcs, num_names = struct.unpack_from("<II", data, eo + 20)[0], struct.unpack_from("<II", data, eo + 24)[0]
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
        ordinal_index = struct.unpack_from("<H", data, ord_off + 2 * i)[0]
        if ordinal_index >= num_funcs:
            continue
        func_rva = struct.unpack_from("<I", data, funcs_off + 4 * ordinal_index)[0]
        out.append((name, func_rva, sha1_dword(name)))
    return image_base, out


def main():
    image_base, exports = parse_exports(NT)
    print("image_base = 0x%X, exports = %d" % (image_base, len(exports)))

    by_hash = {h: (n, r) for n, r, h in exports}
    by_rva = {}
    for n, r, h in exports:
        by_rva.setdefault(r, n)

    # --- 用原始驱动基线反向验证哈希算法 ---
    base_json = os.path.join(HERE, "build", "audit", "gt_orig_triples.json")
    triples = json.load(io.open(base_json, encoding="utf-8"))
    ok = bad = zero = 0
    resolved = {}
    for g, hstr, rstr in triples:
        h = int(hstr, 16)
        r = int(rstr, 16)
        if r == 0:
            zero += 1
            continue
        hit = by_hash.get(h)
        if hit and hit[1] == r:
            ok += 1
            resolved[g] = hit[0]
        else:
            bad += 1
            resolved[g] = ("MISMATCH:%s rva=0x%X vs 0x%X"
                           % (hit[0] if hit else "nohash", hit[1] if hit else -1, r))
    print("baseline verify: OK=%d MISMATCH=%d RVA=0(groups with no export)=%d" % (ok, bad, zero))
    for g in list(resolved):
        if isinstance(resolved[g], str) and resolved[g].startswith("MISMATCH"):
            print("  group %d: %s" % (g, resolved[g]))

    # --- 关心的组 ---
    for g, label in ((0, "GT[0x4159/0x415A]"), (35, "GT[0x41C3]"),
                     (43, "GT[0x41DB]"), (112, "GT[0x42AA] DirectTerminate"),
                     (158, "GT[0x4334]")):
        slot_hash = int(triples[g][1], 16)
        slot_rva = int(triples[g][2], 16)
        nm = by_hash.get(slot_hash)
        print("group %-4d %-26s base=0x%04X hash=0x%08X rva=0x%-8X name=%s"
              % (g, label, 0x4158 + 3 * g, slot_hash, slot_rva,
                 nm[0] if nm else "(unresolved)"))

    io.open(OUT, "w", encoding="utf-8").write(json.dumps(
        {"image_base": image_base,
         "by_hash": {("%08x" % h): [n, r] for h, (n, r) in by_hash.items()},
         "resolved_groups": {str(k): v for k, v in resolved.items()}},
        indent=1))
    print("wrote", OUT)


if __name__ == "__main__":
    sys.exit(main())
