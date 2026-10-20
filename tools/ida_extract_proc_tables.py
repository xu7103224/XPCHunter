# -*- coding: utf-8 -*-
"""从原始驱动 CmdEnumProcessListWin10(0x14005E354) 提取各版本的 EPROCESS 字段映射表，
直接生成可编译的 C 代码。

背景：命令 0xE4 的输出是 N 个 664(0x298) 字节的条目，每个条目把当时那版 Windows 的
EPROCESS 里前端需要的字段搬到固定偏移。原始实现按 NDIS 版本分成 12 个分支，每分支
一套**逐字段显式拷贝**（没有任何循环）。移植时若把它当"从第 54 个字段起拷 N 个"的循环，
就会写越界（实测 80+456*8 = 3728 字节 > 664 → 用户态堆损坏 c0000374）。

用法：
    python tools/ida_extract_proc_tables.py            # 打印到 stdout
    python tools/ida_extract_proc_tables.py out.c      # 写入文件

输出内容：PROC_FIELD_MAP / PROC_LAYOUT 定义、12 张表、SelectProcLayout()。
生成结果已合入 XPCHunterDrv/src/services/Operation.c（EnumProcessListWin10Operation）。
"""

import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from tools.ida_mcp_client import Ida  # noqa: E402

IDB = r"samples\PCHunter_2024.09.02\View++_Driver64.sys.i64"
FUNC = 0x14005E354
SIZE = 0x258D

# 分支点 -> (C 名, 版本范围, 链表偏移)。链表偏移 = 下一个 EPROCESS 在 EPROCESS 内的偏移。
BRANCHES = {
    0x14005E490: ("g_ProcLayout_50001", "0x50001", 0x2F0),
    0x14005E698: ("g_ProcLayout_50002", "0x50002..0x5FFFF", 0x2F8),
    0x14005E8AC: ("g_ProcLayout_60000", "0x60000", 0xFE8),
    0x14005EC11: ("g_ProcLayout_60001", "0x60001", 0x1000),
    0x14005EF70: ("g_ProcLayout_60014", "0x60014", 0x1478),
    0x14005F2E0: ("g_ProcLayout_60015", "0x60015..0x60027", 0xF88),
    0x14005F60A: ("g_ProcLayout_60028", "0x60028..0x60031", 0xF20),
    0x14005F934: ("g_ProcLayout_60032", "0x60032..0x60045", 0xF40),
    0x14005FC5E: ("g_ProcLayout_60046", "0x60046..0x6004F", 0xF20),
    0x14005FF88: ("g_ProcLayout_60050", "0x60050..0x60051", 0xF20),
    0x1400602B2: ("g_ProcLayout_60052", "0x60052", 0xF28),
    0x1400605CF: ("g_ProcLayout_60053", "0x60053+", 0xF08),
}

HEADER = """/* 由 tools/ida_extract_proc_tables.py 从原始 CmdEnumProcessListWin10(0x14005E354)
   的反汇编生成，勿手工编辑。每项：EPROCESS 偏移 -> 输出条目偏移 */
typedef struct _PROC_FIELD_MAP { unsigned int Src; unsigned int Dst; } PROC_FIELD_MAP;
typedef struct _PROC_LAYOUT {
    unsigned int LinkOffset;    /* 下一个 EPROCESS = *(EPROCESS + LinkOffset) */
    unsigned int FieldCount;
    const PROC_FIELD_MAP *pFields;
} PROC_LAYOUT;

"""

SELECTOR = """/* 版本 -> 字段布局。对应原始 0x14005e42b..0x140060598 的比较链。 */
static const PROC_LAYOUT *SelectProcLayout(unsigned int Version)
{
    if (Version >= 0x60000)
    {
        if (Version == 0x60000) return &g_ProcLayout_60000;
        if (Version == 0x60001) return &g_ProcLayout_60001;
        if (Version == 0x60014) return &g_ProcLayout_60014;
        if (Version <  0x60028) return &g_ProcLayout_60015;
        if (Version <  0x60032) return &g_ProcLayout_60028;
        if (Version <  0x60046) return &g_ProcLayout_60032;
        if (Version <  0x60050) return &g_ProcLayout_60046;
        if (Version <  0x60052) return &g_ProcLayout_60050;
        if (Version <  0x60053) return &g_ProcLayout_60052;
        return &g_ProcLayout_60053;
    }
    if (Version == 0x50001) return &g_ProcLayout_50001;
    return &g_ProcLayout_50002;
}
"""


def main(out_path=None):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    import re

    ida = Ida()
    try:
        db = ida.open_db(IDB)
        data = ida.get_bytes(db, FUNC, SIZE)
        insns = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(data, FUNC))

        re_load = re.compile(r"^r\w+, qword ptr \[rsi \+ (0x[0-9a-f]+)\]$")
        re_store = re.compile(r"^qword ptr \[rbx \+ (0x[0-9a-f]+)\], r\w+$")
        re_link = re.compile(r"^rsi, qword ptr \[rsi \+ (0x[0-9a-f]+)\]$")

        sites = sorted(BRANCHES) + [FUNC + SIZE]
        chunks = []
        for k in range(len(sites) - 1):
            a, z = sites[k], sites[k + 1]
            if a not in BRANCHES:
                continue
            name, rng, link = BRANCHES[a]
            pairs, pend, got_link = [], None, None
            for i in insns:
                if not (a <= i.address < z):
                    continue
                m = re_load.match(i.op_str)
                if m:
                    pend = int(m.group(1), 16)
                    continue
                m = re_store.match(i.op_str)
                if m and pend is not None:
                    pairs.append((pend, int(m.group(1), 16)))
                    pend = None
                    continue
                m = re_link.match(i.op_str)
                if m:
                    got_link = int(m.group(1), 16)
            assert got_link == link, (hex(a), got_link, link)
            buf = ["/* %#x : %s，%d 字段，链表偏移 %#x */" % (a, rng, len(pairs), link),
                   "static const PROC_FIELD_MAP %s_Fields[] = {" % name]
            for j in range(0, len(pairs), 4):
                buf.append("    " + " ".join("{ %#x, %#x }," % (s, d)
                                             for s, d in pairs[j:j + 4]))
            buf.append("};")
            buf.append("static const PROC_LAYOUT %s = { %#x, %d, %s_Fields };\n"
                       % (name, link, len(pairs), name))
            chunks.append("\n".join(buf))
        text = HEADER + "\n".join(chunks) + "\n" + SELECTOR
    finally:
        ida.close()

    if out_path:
        open(out_path, "w", encoding="utf-8").write(text)
        print("written %d bytes -> %s" % (len(text), out_path))
    else:
        print(text)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
