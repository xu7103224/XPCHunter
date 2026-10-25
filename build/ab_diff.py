#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐条比对原版与我方驱动的 A/B 采集结果。

比较维度（按严格程度递增）：
  1. 状态（OK / REJ）
  2. 返回码 RES
  3. 输入字节
  4. 输出字节（全等 / 结构等价 / 不同）

对"输出不同"再分三级，因为很多命令返回的是活体内核地址，
随重启变化，不能当成实现差异：
  · STRUCT-SAME  —— 长度相同且仅"内核地址样"的 8 字节字发生差异
  · LEN-DIFF     —— 长度不同
  · DIFF         —— 同长度但差异不限于地址
"""
import re
import sys
from collections import OrderedDict


def load(path):
    """解析 CMD/IN/OUT 三元组。"""
    recs = OrderedDict()
    cur = None
    for ln in open(path, encoding="utf-8", errors="replace"):
        ln = ln.rstrip("\n")
        m = re.match(
            r"^CMD 0x([0-9A-Fa-f]+) INSZ=(\d+) OUTSZ=(\d+) RES=(\d+) (\w+) ERR=(\d+)",
            ln,
        )
        if m:
            cur = int(m.group(1), 16)
            recs[cur] = {
                "insz": int(m.group(2)),
                "outsz": int(m.group(3)),
                "res": int(m.group(4)),
                "status": m.group(5),
                "err": int(m.group(6)),
                "in": "",
                "out": "",
            }
            continue
        if cur is None:
            continue
        if ln.startswith("IN  "):
            v = ln[4:].strip()
            recs[cur]["in"] = "" if v == "-" else v
        elif ln.startswith("OUT "):
            v = ln[4:].strip()
            recs[cur]["out"] = "" if v == "-" else v
    return recs


def is_kptr_bytes(b):
    """判断 8 字节是否像内核地址：高 2 字节为 0xFFFF。"""
    return len(b) == 8 and b[6] == 0xFF and b[7] == 0xFF


def addr_mask_diff(a_bytes, b_bytes):
    """同长度下，差异是否**全部**落在"像内核地址"的 8 字节字上。

    返回 (all_addr_diff, diff_positions)
    """
    n = len(a_bytes)
    diffs = [i for i in range(n) if a_bytes[i] != b_bytes[i]]
    if not diffs:
        return (True, [])
    # 把差异位置按 8 字节对齐分组（输出记录通常 8 字节对齐）
    words = set()
    for i in diffs:
        words.add(i // 8)
    all_addr = True
    for w in words:
        s = w * 8
        aw = a_bytes[s:s + 8]
        bw = b_bytes[s:s + 8]
        if not (is_kptr_bytes(aw) or is_kptr_bytes(bw)):
            all_addr = False
            break
    return (all_addr, diffs)


def main():
    orig_p = sys.argv[1] if len(sys.argv) > 1 else "build/audit/AB_orig.txt"
    mine_p = sys.argv[2] if len(sys.argv) > 2 else "build/audit/AB_mine.txt"

    o = load(orig_p)
    m = load(mine_p)

    keys = sorted(set(o) | set(m))
    stats = {
        "identical": [],
        "status_diff": [],
        "res_diff": [],
        "in_diff": [],
        "struct_same": [],
        "len_diff": [],
        "diff": [],
        "only_orig": [],
        "only_mine": [],
    }

    print("=" * 78)
    print(f"原版: {orig_p}  ({len(o)} 条)")
    print(f"我方: {mine_p}  ({len(m)} 条)")
    print("=" * 78)

    for k in keys:
        a, b = o.get(k), m.get(k)
        tag = f"0x{k:03X}"
        if a is None:
            stats["only_mine"].append((tag, b)); continue
        if b is None:
            stats["only_orig"].append((tag, a)); continue
        if a["status"] != b["status"]:
            stats["status_diff"].append((tag, a, b)); continue
        if a["res"] != b["res"]:
            stats["res_diff"].append((tag, a, b)); continue
        if a["in"] != b["in"]:
            stats["in_diff"].append((tag, a, b)); continue
        if a["out"] == b["out"]:
            stats["identical"].append((tag, a, b)); continue
        if not a["out"] or not b["out"]:
            stats["len_diff"].append((tag, a, b)); continue
        ba = bytes.fromhex(a["out"])
        bb = bytes.fromhex(b["out"])
        if len(ba) != len(bb):
            stats["len_diff"].append((tag, a, b)); continue
        all_addr, _ = addr_mask_diff(ba, bb)
        if all_addr:
            stats["struct_same"].append((tag, a, b))
        else:
            stats["diff"].append((tag, a, b))

    def dump(name, items, detail=False):
        if not items:
            return
        print(f"\n### {name}  ({len(items)} 条)")
        for it in items:
            if len(it) == 2:
                tag, r = it
                print(f"  {tag}  仅存在于一方: status={r['status']} res={r['res']}")
                continue
            tag, a, b = it
            print(f"  {tag}  orig: {a['status']}/res={a['res']}/out={len(a['out'])//2}B"
                  f"   mine: {b['status']}/res={b['res']}/out={len(b['out'])//2}B")
            if detail and a["out"] and b["out"] and len(a["out"]) == len(b["out"]):
                for i in range(0, len(a["out"]), 32):
                    seg_a = a["out"][i:i+32]
                    seg_b = b["out"][i:i+32]
                    if seg_a != seg_b:
                        print(f"      +{i//2:04X} orig={seg_a}")
                        print(f"             mine={seg_b}")

    print(f"\n{'='*78}\n汇总\n{'='*78}")
    order = [
        ("完全一致（状态+返回码+输入+输出）", "identical"),
        ("结构等价（差异仅为内核地址）", "struct_same"),
        ("输出长度不同", "len_diff"),
        ("输出字节不同", "diff"),
        ("返回码不同", "res_diff"),
        ("输入不同", "in_diff"),
        ("状态不同（OK vs REJ）", "status_diff"),
        ("仅原版有记录", "only_orig"),
        ("仅我方有记录", "only_mine"),
    ]
    for label, key in order:
        print(f"  {label:<32} {len(stats[key]):>4} 条")

    total = len(stats["identical"]) + len(stats["struct_same"])
    print(f"\n  可比条目总数: {len(keys)}")
    print(f"  输出对齐（含结构等价）: {total} / {len(keys)}")

    for label, key in order:
        if key in ("identical",):
            continue
        dump(label, stats[key], detail=(key in ("diff", "len_diff")))

    return 0


if __name__ == "__main__":
    sys.exit(main())