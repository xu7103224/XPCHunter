# 核验 ParseNtRelocSection：比对原始与复刻的立即数常量与内存偏移
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

def collect(data, off, size):
    consts, offsets = set(), set()
    for i in md.disasm(data[off:off+size], 0):
        # 立即数
        for m in re.finditer(r', (0x[0-9a-f]+)$', i.op_str):
            consts.add(int(m.group(1), 16))
        for m in re.finditer(r', (-?\d+)$', i.op_str):
            v = int(m.group(1))
            if v > 0: consts.add(v)
        # 内存偏移 [reg + 0xNN]
        for m in re.finditer(r'\[(\w+) ([+-]) (0x[0-9a-f]+)\]', i.op_str):
            offsets.add(int(m.group(3), 16))
    return consts, offsets

# 原始函数：0x14000E634，大小 0x4A6
oc, oo = collect(do, o2o(0x14000E634), 0x4A6)

mp = open(r'build\bin\Release\x64\XPCHunterDrv.map', encoding='utf-8', errors='ignore').read()
syms = sorted((int(a, 16), n) for n, a in re.findall(r'\s([A-Za-z_]\w*)\s+([0-9a-f]{16})\s+f', mp))
nva = next(a for a, n in syms if n == 'ParseNtRelocSection')
nsz = next(a for a, n in syms if a > nva) - nva
print(f'复刻 ParseNtRelocSection @ {nva:#x}, {nsz:#x} bytes (原始 0x4A6 = 1190)')
nc, no = collect(dn, o2n(nva), nsz)

print()
print('=== 关键常量比对（节区标记 / 构建号 / 输出表步长）===')
KEY = {0x559:'节区标记 0x559', 0x547:'重定位标记 0x547', 0x50E:'SectionFlags 1294',
       0x558:'节区标记 0x558', 0x473:'标记 1139', 0x512:'节区标记 0x512',
       0x40000:'对齐 0x40000', 0xC0916A2:'Win10 重定位节区名', 0x188:'节区名 0x188',
       0x23F0:'构建号阈值 0x23F0', 0x914:'GT 构建号索引', 0x8A8:'GT 导出表索引',
       0x186:'重定位范围上限', 0x1F4:'条目上限 500', 0x1E:'节区轮数上限 30',
       0x118:'SectionNamePtr 偏移', 0xF0:'SizeOfRawData 偏移', 0xDC:'MiscInfo 偏移',
       0x90:'RelocEntryIndex 偏移', 0x88:'SectionAlignment 偏移', 0x78:'RawDataSize 偏移',
       0x70:'SectionName 偏移', 0x58:'SectionIndex 偏移', 0x50:'Characteristics 偏移',
       0x40:'VirtualSize 偏移', 0x38:'VirtualAddress 偏移'}
ok = True
for v, name in sorted(KEY.items()):
    a, b = v in oc, v in nc
    mark = '✓' if a == b else '✗'
    if a != b: ok = False
    print(f'  {mark} {name:28s} 原始={"有" if a else "无"}  复刻={"有" if b else "无"}')
print()
print('结论:', '全部关键常量一致 ✓' if ok else '存在差异 ✗')
print()
print(f'原始常量数 {len(oc)}，复刻常量数 {len(nc)}')
print('原始有而复刻无的常量:', sorted(hex(x) for x in oc - nc)[:12])
