# 核验 DisableObjectProtectEx：原始 vs 复刻 的关键常量与调用序列
import pefile, re
from capstone import *

ORIG = r'samples\PCHunter_2024.09.02\View++_Driver64.sys'
NEW = r'build\bin\Release\x64\XPCHunterDrv.sys'

def load(path):
    pe = pefile.PE(path); data = open(path, 'rb').read()
    secs = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]
    def va2off(va):
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        for sva, sz, raw in secs:
            if sva <= rva < sva + sz: return raw + (rva - sva)
    return pe, data, va2off

po, do, o2o = load(ORIG)
pn, dn, o2n = load(NEW)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def dis(data, off, va, n=150):
    out = []
    for i in md.disasm(data[off:off + 900], va):
        out.append(f'{i.mnemonic} {i.op_str}')
        if len(out) >= n or i.mnemonic == 'ret': break
    return out

orig_ins = dis(do, o2o(0x140007D54), 0x140007D54)

mp = open(r'build\bin\Release\x64\XPCHunterDrv.map', encoding='utf-8', errors='ignore').read()
m = re.search(r'DisableObjectProtectEx\s+([0-9a-f]{16})\s+f', mp)
nva = int(m.group(1), 16) if m else None
print(f'复刻 DisableObjectProtectEx @ {nva:#x}' if nva else '未找到符号')
new_ins = dis(dn, o2n(nva), nva)

def feats(ins, label):
    t = '\n'.join(ins)
    checks = {
        'GtRead(0x421D) RtlInitUnicodeString': '0x421d' in t,
        'GtRead(0x4238) 打开对象':              '0x4238' in t,
        'GtRead(0x41C6) FsControl':            '0x41c6' in t,
        'GtRead(0x4223) 关闭句柄':              '0x4223' in t,
        'GtRead(0x4334) 释放池':                '0x4334' in t,
        '控制码 0xf000f':                       '0xf000f' in t,
        'OBJECT_ATTRIBUTES Length=0x30':       '0x30' in t,
        'Attributes=0x240':                    '0x240' in t,
        'ExAlloc 大小 0x100000':               '0x100000' in t,
        'WalkObjectTypeList 深度 0x20000':      '0x20000' in t,
        '编码名 43005ch / 6c0061h':            ('0x43005c' in t and '0x6c0061' in t),
        '编码名 62006ch / 630061h / 6bh':      ('0x62006c' in t and '0x630061' in t and '0x6b' in t),
    }
    print(f'--- {label}')
    for k, v in checks.items():
        print(f'    {"✓" if v else "✗"} {k}')
    return checks

co = feats(orig_ins, '原始')
cn = feats(new_ins, '复刻')
print()
diff = [k for k in co if co[k] != cn[k]]
print('结论:', '全部特征一致 ✓' if not diff else f'不一致项: {diff}')
print()
print('复刻调用序列（含调用与常量装载）:')
for s in new_ins:
    if s.startswith('call') or '0x' in s and any(x in s for x in ['0xf000f', '0x240', '0x30', '0x100000', '0x20000', '0x43005c', '0x6c0061', '0x62006c', '0x630061', '0x6b']):
        print('   ', s)
