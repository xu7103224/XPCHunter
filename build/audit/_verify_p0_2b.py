# 验证 P0-2b：与原始逐指令比对关键指令（尤其是 FsInformationClass 字节偏移）
import pefile, re, struct
from capstone import *

ORIG = r'samples\PCHunter_2024.09.02\View++_Driver64.sys'
NEW = r'build\bin\Release\x64\XPCHunterDrv.sys'

def loader(path):
    pe = pefile.PE(path)
    data = open(path, 'rb').read()
    secs = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData) for s in pe.sections]
    def va2off(va):
        rva = va - pe.OPTIONAL_HEADER.ImageBase
        for sva, sz, raw in secs:
            if sva <= rva < sva + sz:
                return raw + (rva - sva)
        return None
    return pe, data, va2off

po, do, oo2 = loader(ORIG)
pn, dn, on2 = loader(NEW)

# 复刻中的地址（从 map 取）
mp = open(r'build\bin\Release\x64\XPCHunterDrv.map', encoding='utf-8', errors='ignore').read()
def sym(name):
    m = re.search(re.escape(name) + r'\s+([0-9a-f]{16})\s+f', mp)
    return int(m.group(1), 16) if m else None

md = Cs(CS_ARCH_X86, CS_MODE_64)

def show(label, data, va2off, va, count=70):
    off = va2off(va)
    print(f'--- {label} @ {va:#x}')
    out = []
    for i in md.disasm(data[off:off + 600], va):
        out.append(f'   {i.address:#x}: {i.mnemonic} {i.op_str}')
        if len(out) >= count or i.mnemonic == 'ret':
            break
    print('\n'.join(out))
    return out

print('=' * 96)
print('MiniFilterPreVolumeDismount：原始 vs 复刻')
print('=' * 96)
o_ins = show('原始', do, oo2, 0x140018EA0)
n_va = sym('MiniFilterPreVolumeDismount')
n_ins = show('复刻', dn, on2, n_va)

print()
print('=' * 96)
print('关键指令比对：FsInformationClass 字节读取')
print('=' * 96)
pat = re.compile(r'mov (\w+), byte ptr \[(\w+)\+0x(\w+)\]')
for tag, ins in (('原始', o_ins), ('复刻', n_ins)):
    hits = [x.strip() for x in ins if 'byte ptr' in x and '+' in x and 'mov' in x]
    # 找读取 Iopb 派生寄存器偏移的那条
    for h in hits:
        print(f'  {tag}: {h}')
print()

print('=' * 96)
print('CheckVolumeFileExists：原始 vs 复刻')
print('=' * 96)
o2_ins = show('原始', do, oo2, 0x140019280, count=40)
n2_va = sym('CheckVolumeFileExists')
n2_ins = show('复刻', dn, on2, n2_va, count=40)
