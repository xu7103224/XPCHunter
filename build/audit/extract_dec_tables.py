#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从原始驱动 PE 按**正确** RVA→文件偏移映射抽取全部 PE 解码表，生成 DecodeTables.c 的表数据段。

【根因】旧抽取脚本把 RVA 直接当文件偏移用（.data/.rdata 的 VA 与 PointerToRawData 差 0x1000），
        导致每张表的字节内容整体取自 RVA+0x1000 处 —— 整个指令解码器一直在用错位数据。

权威表清单（由 IDA 交叉引用确定，每张表恰好被一个解码器函数引用）：
  0x96A30  320   g_PeDecodeTableDefault       DecodeOpcodeTableWithPrefix / DecodeOpcodeTableDirect 默认表
  0x96A50  5120  g_PeLegacyDescrambleTable    InitPESectionReadContext（模式 2）
  0x97E50  5120  g_PeDataDescrambleTable      InitPESectionReadContext
  0x99250  5120  g_PeDecodeTableLegacy2       DecodeOpcodeTable16_32_64 默认表 / ClassifyPESectionType(+0xDC) / WithOffset(+0x100)
  0x9A650  5120  g_PeDecodeTableMode0         DecodeOpcodeTable16_32_64 子类型 0
  0x9BA50  5120  g_PeDecodeTableMode3         DecodeOpcodeTable16_32_64 子类型 3
  0x9CE50  5120  g_PeDecodeTableMode4         DecodeOpcodeTable16_32_64 子类型 4
  0x9E250  128   g_PeDecodeTablePrefixPtrA    DecodeOpcodeTableWithPrefix 指针表（16 项）
  0x9E2D0  128   g_PeDecodeTablePrefixPtrB    DecodeOpcodeTableWithPrefix 指针表（16 项）
  0x9E5D0  960   g_PeDecodeTableGrp1          DecodeOpcodeTableGroup1
  0x9E990  320   g_PeDecodeTableGrp2          DecodeOpcodeTableGroup2
  0x9EAD0  320   g_PeDecodeTableGrp3          DecodeOpcodeTableGroup3
  0x9EC10  160   g_PeDecodeTableGrp4          DecodeOpcodeTableGroup4
  0x9ECB0  160   g_PeDecodeTablePrefixM0      DecodeOpcodeByPrefixGroup
  0x9ED50  160   g_PeDecodeTablePrefixM1      DecodeOpcodeByPrefixGroup
  0x9EDF0  160   g_PeDecodeTablePrefixM3      DecodeOpcodeByPrefixGroup
  0x9EE90  160   g_PeDecodeTableGrp5          DecodeOpcodeTableGroup5
  0x9EF30  160   g_PeDecodeTableGrp6          DecodeOpcodeTableGroup6
  0x9EFD0  160   g_PeDecodeTableOneByte       DecodeOneByteOpcodeTable
  0x9F070  320   g_PeDecodeTableTwoByte0F     DecodeTwoByteOpcode0F
  0x9F1B0  320   g_PeDecodeTableTwoByte38     DecodeTwoByteOpcode0F38
  0x9F2F0  320   g_PeDecodeTableTwoByte3A     DecodeTwoByteOpcode0F3A
  0x9F430  160   g_PeDecodeTableModrmReg      DecodeModrmOpcodeTable
  0x9F4D0  160   g_PeDecodeTableModrmMem      DecodeModrmOpcodeTable
  0x9F570  160   g_PeDecodeTableOpcodeByte    DecodeOpcodeByte
  0x9F610  5120  g_PeDecodeTableModrmOpcode   DecodeOpcodeWithModrm
  0xA0A10  11520 多字节操作码表区（8 × 1440）  DecodeMultiByteOpcode
  0xA3710  64    g_PeMultiByteTable1          DecodeMultiByteOpcode 指针表（8 项）
  0xA3750  64    g_PeMultiByteTable2          DecodeMultiByteOpcode 指针表（8 项）
  0xA3790  1600  子表区（5 × 320）            0x9E250/0x9E2D0 指针表的目标
  0xA3DD0  64    g_PeDecodeFunctionTable      ReadPESectionEntry 解码函数表
  0xCCEC0  128   （全 0，虚拟填充区）          DecodeOpcodeTableWithPrefix 子类型 3 分支
  0xCCF40  128   （全 0，虚拟填充区）          DecodeOpcodeTableDirect
"""
import struct
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SYS = os.path.join(ROOT, 'samples', 'PCHunter_2024.09.02', 'View++_Driver64.sys')

# 主表区：0x96A30 .. 0xA3710（含全部 20 字节/条目的解码表 + 8 张多字节表）
REGION1_RVA, REGION1_SIZE = 0x96A30, 0xA3710 - 0x96A30
# 子表区：0xA3790 .. 0xA3DD0（5 × 320 字节，指针表目标）
SUB_RVA, SUB_SIZE = 0xA3790, 0xA3DD0 - 0xA3790
# 多字节指针表位置（在主表区内）
MB1_RVA, MB2_RVA = 0xA3710, 0xA3750

TABLES = [
    ('g_PeDecodeTableDefault',      0x96A30,  320),
    ('g_PeLegacyDescrambleTable',   0x96A50, 5120),
    ('g_PeDataDescrambleTable',     0x97E50, 5120),
    ('g_PeDecodeTableLegacy2',      0x99250, 5120),
    ('g_PeDecodeTableMode0',        0x9A650, 5120),
    ('g_PeDecodeTableMode3',        0x9BA50, 5120),
    ('g_PeDecodeTableMode4',        0x9CE50, 5120),
    ('g_PeDecodeTableGrp1',         0x9E5D0,  960),
    ('g_PeDecodeTableGrp2',         0x9E990,  320),
    ('g_PeDecodeTableGrp3',         0x9EAD0,  320),
    ('g_PeDecodeTableGrp4',         0x9EC10,  160),
    ('g_PeDecodeTablePrefixM0',     0x9ECB0,  160),
    ('g_PeDecodeTablePrefixM1',     0x9ED50,  160),
    ('g_PeDecodeTablePrefixM3',     0x9EDF0,  160),
    ('g_PeDecodeTableGrp5',         0x9EE90,  160),
    ('g_PeDecodeTableGrp6',         0x9EF30,  160),
    ('g_PeDecodeTableOneByte',      0x9EFD0,  160),
    ('g_PeDecodeTableTwoByte0F',    0x9F070,  320),
    ('g_PeDecodeTableTwoByte38',    0x9F1B0,  320),
    ('g_PeDecodeTableTwoByte3A',    0x9F2F0,  320),
    ('g_PeDecodeTableModrmReg',     0x9F430,  160),
    ('g_PeDecodeTableModrmMem',     0x9F4D0,  160),
    ('g_PeDecodeTableOpcodeByte',   0x9F570,  160),
    ('g_PeDecodeTableModrmOpcode',  0x9F610, 5120),
    ('g_PeDecodeTableMultiByte',    0xA0A10, 11520),
]


def load_pe():
    d = open(SYS, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    magic = struct.unpack_from('<H', d, pe + 24)[0]
    so = pe + 24 + (240 if magic == 0x20b else 224)
    secs = []
    for i in range(nsec):
        o = so + 40 * i
        nm = d[o:o + 8].rstrip(b'\x00').decode()
        vs, va, rs, pr = struct.unpack_from('<IIII', d, o + 8)
        secs.append((nm, va, vs, pr, rs))
    return d, secs


def rva2off(secs, rva):
    for nm, va, vs, pr, rs in secs:
        if va <= rva < va + max(vs, rs):
            off = rva - va
            if off < rs:
                return pr + off          # 在文件内
            return None                  # 虚拟填充区（全 0）
    return None


def read_rva(data, secs, rva, size):
    off = rva2off(secs, rva)
    if off is None:
        return b'\x00' * size
    return data[off:off + size]


def cbytes(name, blob, rva, comment):
    out = []
    out.append('// %s — 原始 RVA 0x%X，%d 字节%s' % (name, rva, len(blob), comment))
    out.append('const UCHAR %s[%d] = {' % (name, len(blob)))
    for i in range(0, len(blob), 16):
        chunk = blob[i:i + 16]
        out.append('    ' + ' '.join('0x%02X,' % b for b in chunk))
    out.append('};')
    out.append('')
    return '\n'.join(out)


def main():
    data, secs = load_pe()

    # ---------- 1) 证明旧内容的 0x1000 错位 ----------
    print('=== 旧表内容错位验证（旧内容 == 原始 RVA+0x1000 处字节）===')
    src = os.path.join(ROOT, 'XPCHunterDrv', 'src', 'framework', 'DecodeTables.c')
    txt = open(src, encoding='utf-8', errors='replace').read()
    import re
    bad = ok = 0
    for name, rva, size in TABLES:
        m = re.search(r'const UCHAR %s\[%d\]\s*=\s*\{(.*?)\n\};' % (name, size), txt, re.S)
        if not m:
            continue
        body = [int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', m.group(1))]
        cur = bytes(body[:size])
        right = read_rva(data, secs, rva, size)
        shifted = read_rva(data, secs, rva + 0x1000, size)
        tag = 'RIGHT' if cur == right else ('SHIFT+1000' if cur == shifted else 'UNKNOWN')
        if tag == 'RIGHT':
            ok += 1
        else:
            bad += 1
        print('  %-30s %s' % (name, tag))
    print('  => 正确 %d 张，错误 %d 张' % (ok, bad))

    # ---------- 2) 指针表内容 ----------
    print()
    print('=== 指针表原始内容（RVA 形式）===')
    for nm, rva in (('off_14009E250', 0x9E250), ('off_14009E2D0', 0x9E2D0),
                    ('off_1400A3710', 0xA3710), ('off_1400A3750', 0xA3750),
                    ('qword_1400CCEC0', 0xCCEC0), ('qword_1400CCF40', 0xCCF40)):
        raw = read_rva(data, secs, rva, 128)
        vals = [struct.unpack_from('<Q', raw, i * 8)[0] for i in range(16)]
        nz = [(i, v) for i, v in enumerate(vals) if v]
        print('  %-16s 非空项: %s' % (nm, ', '.join('[%d]=0x%X' % (i, v) for i, v in nz) or '（全 0）'))

    # ---------- 3) 生成表数据段 ----------
    print()
    print('=== 生成 ===')
    parts = []
    parts.append('// ============================================================')
    parts.append('// PE 指令解码表数据 — 由 build/audit/extract_dec_tables.py 从原始驱动')
    parts.append('//   View++_Driver64.sys 按正确 RVA→文件偏移映射机械抽取，禁止手改。')
    parts.append('//')
    parts.append('// 【重要】这些表是原始驱动 .data 段 0x96A30~0xA3DD0 的**逐字节镜像**。')
    parts.append('//   旧版本抽取时把 RVA 当文件偏移用（.data 的 VA=0x94000 与 PointerToRawData=0x93000')
    parts.append('//   相差 0x1000），导致每张表的内容整体取自 RVA+0x1000 —— 解码器一直在用错位数据。')
    parts.append('//   本文件内容可用下列命令复验：')
    parts.append('//     python build/audit/extract_dec_tables.py')
    parts.append('// ============================================================')
    parts.append('')
    parts.append('#include "XPCHunterDrv.h"')
    parts.append('')
    parts.append('// ---------- 主表区 0x96A30 ~ 0xA3710（含全部 20 字节/条目解码表 + 8 张多字节表）----------')
    parts.append('')

    r1 = read_rva(data, secs, REGION1_RVA, REGION1_SIZE)
    parts.append(cbytes('g_PeDecodeTableRegion', r1, REGION1_RVA,
                        '（含指针表槽位，槽位内为原始 RVA 值，仅供字节保真，代码不得使用）'))

    # 偏移宏单独输出到头文件（供所有编译单元使用）
    mac = []
    mac.append('// ============================================================')
    mac.append('// PE 解码表偏移宏 — 由 build/audit/extract_dec_tables.py 生成，禁止手改。')
    mac.append('// 所有表都是原始驱动 .data 段主表区 0x96A30~0xA3710 的**切片**，')
    mac.append('// 用统一镜像数组 + 偏移宏表达，保证逐字节保真且无切片/重叠错误。')
    mac.append('// ============================================================')
    mac.append('extern const UCHAR g_PeDecodeTableRegion[];    /* RVA 0x96A30, %d 字节 */' % REGION1_SIZE)
    mac.append('extern const UCHAR g_PeDecodeTableSubGroup[];  /* RVA 0xA3790, %d 字节 */' % SUB_SIZE)
    mac.append('')
    for name, rva, size in TABLES:
        off = rva - REGION1_RVA
        assert 0 <= off and off + size <= REGION1_SIZE, name
        mac.append('#define %s  (&g_PeDecodeTableRegion[0x%05X])   /* RVA 0x%X, %d 字节 */'
                   % (name, off, rva, size))
    mac.append('')
    mac.append('/* 子表区 5 × 320 字节 */')
    for i in range(5):
        mac.append('#define g_PeDecodeTableSubGroup%d  (&g_PeDecodeTableSubGroup[0x%03X])  /* RVA 0x%X */'
                   % (i, i * 320, SUB_RVA + i * 320))
    mac.append('')
    mac.append('/* 指针表（原始为 RVA 数组，本移植用本方地址重建） */')
    mac.append('extern const ULONG64 g_PeDecodeTablePrefixPtrA[16];  /* 原 RVA 0x9E250 */')
    mac.append('extern const ULONG64 g_PeDecodeTablePrefixPtrB[16];  /* 原 RVA 0x9E2D0 */')
    mac.append('extern const ULONG64 g_PeMultiByteTable1[8];          /* 原 RVA 0xA3710 */')
    mac.append('extern const ULONG64 g_PeMultiByteTable2[8];          /* 原 RVA 0xA3750 */')
    mac.append('extern const ULONG64 g_PeDecodeTableSubtypePtr[16];   /* 原 RVA 0xCCEC0（全 0）*/')
    mac.append('extern const ULONG64 g_PeDecodeTableDirectPtr[16];    /* 原 RVA 0xCCF40（全 0）*/')
    mac.append('extern const ULONG64 g_PeDecodeFunctionTable[8];      /* 原 RVA 0xA3DD0 */')
    mac.append('extern const ULONG g_PeDataTypeSizeTable[8];')
    mac.append('extern const ULONG g_PeDataTypeSubTypeTable[4];')
    mac.append('')
    open(os.path.join(ROOT, 'build', 'audit', '_dec_tables_macros.h'), 'w', encoding='utf-8').write('\n'.join(mac) + '\n')
    print('  已写出 build/audit/_dec_tables_macros.h（%d 行）' % (len(mac) + 1))
    parts.append('')

    parts.append('// ---------- 子表区 0xA3790 ~ 0xA3DD0（5 × 320 字节，0x9E250/0x9E2D0 指针表的目标）----------')
    parts.append('')
    sub = read_rva(data, secs, SUB_RVA, SUB_SIZE)
    parts.append(cbytes('g_PeDecodeTableSubGroup', sub, SUB_RVA, ''))
    for i in range(5):
        parts.append('#define g_PeDecodeTableSubGroup%d  (&g_PeDecodeTableSubGroup[0x%03X])  /* RVA 0x%X */'
                     % (i, i * 320, SUB_RVA + i * 320))
    parts.append('')

    # ---------- 4) 指针表（用本方地址重建，不依赖重定位） ----------
    parts.append('// ---------- 指针表：原始为 RVA 数组，须用本方地址重建 ----------')
    parts.append('')
    parts.append('// DecodeOpcodeTableWithPrefix 用：索引 = 操作码高半字节(0..15)')
    pA = [0x0A3790, 0x0A38D0] + [None] * 14
    parts.append('const ULONG64 g_PeDecodeTablePrefixPtrA[16] = {')
    for i, t in enumerate(pA):
        parts.append('    %s,  /* [%d] */' % ('(ULONG64)&g_PeDecodeTableSubGroup[0x%03X]' % (t - 0xA3790)
                                              if t else '0', i))
    parts.append('};')
    parts.append('')
    pB = {0: 0x0A3A10, 1: 0x0A3B50, 8: 0x0A3C90}
    parts.append('// DecodeOpcodeTableWithPrefix 用（子类型字节 == 0 时）')
    parts.append('const ULONG64 g_PeDecodeTablePrefixPtrB[16] = {')
    for i in range(16):
        t = pB.get(i)
        parts.append('    %s,  /* [%d] */' % ('(ULONG64)&g_PeDecodeTableSubGroup[0x%03X]' % (t - 0xA3790)
                                              if t else '0', i))
    parts.append('};')
    parts.append('')
    parts.append('// DecodeMultiByteOpcode 用（8 项，指向主表区内的多字节表）')
    parts.append('const ULONG64 g_PeMultiByteTable1[8] = {')
    for i in range(8):
        parts.append('    (ULONG64)&g_PeDecodeTableRegion[0x%05X],  /* RVA 0x%X */'
                     % (0xA0A10 + i * 0x5A0 - REGION1_RVA, 0xA0A10 + i * 0x5A0))
    parts.append('};')
    parts.append('')
    parts.append('const ULONG64 g_PeMultiByteTable2[8] = {')
    for i in range(8):
        parts.append('    (ULONG64)&g_PeDecodeTableRegion[0x%05X],  /* RVA 0x%X */'
                     % (0xA0AB0 + i * 0x5A0 - REGION1_RVA, 0xA0AB0 + i * 0x5A0))
    parts.append('};')
    parts.append('')
    parts.append('// 原始 0xCCEC0 / 0xCCF40 位于 .data 虚拟填充区（超出 SizeOfRawData），')
    parts.append('// 加载后恒为全 0 —— 引用它们的分支在原始驱动中即为死代码。此处按原样保留全 0。')
    parts.append('const ULONG64 g_PeDecodeTableSubtypePtr[16] = {0};   /* 原 RVA 0xCCEC0 */')
    parts.append('const ULONG64 g_PeDecodeTableDirectPtr[16] = {0};    /* 原 RVA 0xCCF40 */')
    parts.append('')

    out = '\n'.join(parts)
    dst = os.path.join(ROOT, 'build', 'audit', '_dec_tables_generated.c')
    open(dst, 'w', encoding='utf-8').write(out)
    print('  已写出 %s（%d 行）' % (dst, out.count('\n') + 1))

    # ---------- 5) 自检：区域哈希 ----------
    import hashlib
    print()
    print('  主表区 0x96A30..0xA3710 sha1 = %s' % hashlib.sha1(r1).hexdigest())
    print('  子表区 0xA3790..0xA3DD0 sha1 = %s' % hashlib.sha1(sub).hexdigest())


if __name__ == '__main__':
    main()
