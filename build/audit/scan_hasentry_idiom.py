#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 capstone 判定原始每个 handler 的 HasEntry 惯用法，并给我方对应函数名。"""
import struct
import capstone

ORIG = 'samples/PCHunter_2024.09.02/View++_Driver64.sys'
MINE = 'build/bin/Release/x64/XPCHunterDrv.sys'
BASE = 0x140000000
DISPATCH = 0x14008C2D4

HANDLERS = [
    (0, 0x8bcfc, 'DecodeOpcodeWithPrefix'),
    (1, 0x8b770, 'DecodeModrmInstruction'),
    (2, 0x8bf20, 'DecodeOpcodeReadByte'),
    (3, 0x8a904, 'ReadPESectionFieldByte'),
    (4, 0x8c008, 'DecodeReadWordImmediate'),
    (5, 0x8c0f8, 'DecodeReadSizeDependentImmediate'),
    (6, 0x8a93c, 'ReadPESectionAsmField'),
    (7, 0x8aa0c, 'SerializeDataToBuffer'),
    (8, 0x8abb8, 'ClassifyDataTypeV1'),
    (9, 0x8c058, 'DecodeReadDwordImmediate'),
    (10, 0x8c0a8, 'DecodeReadQwordImmediate'),
    (11, 0x8aed0, 'DecodeOpcodeTable16_32_64'),
    (12, 0x8b108, 'DecodeOpcodeTableWithOffset'),
    (13, 0x8b180, 'DecodeOpcodeTableGroup1'),
    (14, 0x8b238, 'DecodeOpcodeTableGroup2'),
    (15, 0x8b2b0, 'DecodeOpcodeTableGroup3'),
    (16, 0x8b484, 'DecodeOpcodeWithModrm'),
    (17, 0x8b588, 'DecodeOpcodeTableGroup4'),
    (18, 0x8b5ec, 'DecodeOpcodeByPrefixGroup'),
    (19, 0x8b6a8, 'DecodeOpcodeTableGroup5'),
    (20, 0x8b70c, 'DecodeOpcodeTableGroup6'),
    (21, 0x8ba3c, 'DecodeOneByteOpcodeTable'),
    (22, 0x8baa0, 'DecodeTwoByteOpcode0F'),
    (23, 0x8bb14, 'DecodeTwoByteOpcode0F38'),
    (24, 0x8bb88, 'DecodeTwoByteOpcode0F3A'),
    (25, 0x8bbfc, 'DecodeModrmOpcodeTable'),
    (26, 0x8bc98, 'DecodeOpcodeByte'),
    (27, 0x8bf1c, 'DecodeOpcodeStubZero'),
    (32, 0x8b338, 'DecodeMultiByteOpcode'),
    (33, 0x8bf68, 'DecodeReadImmediateValue'),
    (34, 0x8a87c, 'ReadPESectionField'),
    (35, 0x8afa0, 'DecodeOpcodeTableWithPrefix'),
    (36, 0x8b080, 'DecodeOpcodeTableDirect'),
]


def text_of(path):
    f = open(path, 'rb').read()
    pe = struct.unpack_from('<I', f, 0x3c)[0]
    nsec = struct.unpack_from('<H', f, pe + 6)[0]
    opt = struct.unpack_from('<H', f, pe + 20)[0]
    for i in range(nsec):
        o = pe + 24 + opt + i * 40
        if f[o:o + 8].rstrip(b'\x00').decode('latin1') != '.text':
            continue
        vsz, va, rsz, ra = struct.unpack_from('<IIII', f, o + 8)
        return f[ra:ra + rsz], BASE + va
    raise SystemExit('no .text')


def classify(insns):
    """insns: 该 handler 序言后到首个 dispatch call 之前的指令列表。"""
    for a in range(len(insns) - 3):
        i0, i1, i2, i3 = insns[a:a + 4]
        if (i0.mnemonic == 'cmp' and i0.op_str.startswith('byte ptr [')
                and i0.op_str.endswith(', bl')
                and i1.mnemonic.startswith('j')
                and i2.mnemonic == 'cmp' and i2.op_str.startswith('byte ptr [')
                and i2.op_str.endswith(', bl')
                and i3.mnemonic.startswith('j')):
            return 'AND'
    for i in insns:
        if i.mnemonic == 'movzx' and 'word ptr [' in i.op_str:
            return 'OR(word)'
    for i in insns:
        if i.mnemonic == 'cmp' and i.op_str.startswith('byte ptr [') and i.op_str.endswith(', bl'):
            return 'single-byte-cmp'
    return 'none'


def main():
    seg, tva = text_of(ORIG)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    insns = list(md.disasm(seg, tva))
    disp = [i.address for i in insns if i.mnemonic == 'call' and i.op_str == hex(DISPATCH)]
    print(f'{"idx":>3} {"name":34s} {"handler":>12s} {"idiom":>16s}')
    for idx, rva, nm in HANDLERS:
        start = BASE + rva
        # 该函数内首个 dispatch call
        fc = None
        for c in disp:
            if start <= c < start + 0x220:
                fc = c
                break
        if fc is None:
            print(f'{idx:>3} {nm:34s} {hex(start):>12s} {"(no dispatch)":>16s}')
            continue
        sub = [i for i in insns if start <= i.address < fc]
        print(f'{idx:>3} {nm:34s} {hex(start):>12s} {classify(sub):>16s}')


if __name__ == '__main__':
    main()